use clap::{App, Arg};
use pcap::Capture;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use std::path::Path;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{self, AsyncWriteExt};
use tokio::task;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = App::new("pcap splitter")
        .about("Split a pcap file into multiple files (one packet per file)")
        .arg(
            Arg::with_name("directory")
                .help("Read files from a directory. It will not read recursively")
                .conflicts_with("file")
                .long("dir")
                .short("d")
                .required_unless("file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .help("parse a single pacap file")
                .long("file")
                .short("f")
                .takes_value(true)
                .conflicts_with("directory"),
        )
        .arg(
            Arg::with_name("filter")
                .help("BPF query to filter out packages (Ref. https://biot.com/capstats/bpf.html)")
                .long("query")
                .short("q")
                .takes_value(true),
        )
        .get_matches();
    let input_path = match args.value_of("directory") {
        Some(path) => path,
        None => args.value_of("file").unwrap(),
    };
    let filter = Arc::new(String::from(args.value_of("filter").unwrap_or("")));
    let path_str = Arc::new(String::from(input_path));
    process_input(path_str, filter).await?;

    Ok(())
}

async fn process_input(path_str: Arc<String>, filter: Arc<String>) -> io::Result<()> {
    let input_path = Path::new(path_str.as_str());
    let mut join = Vec::new();
    if input_path.is_dir() {
        let mut entries = fs::read_dir(input_path).await?;
        while let Some(file) = entries.next_entry().await? {
            let f = Arc::new(String::from(file.path().to_str().unwrap()));
            let filter = filter.clone();
            join.push(task::spawn(async move { split_pcap(f, filter).await }));
        }
    } else {
        join.push(task::spawn(async move {
            split_pcap(path_str.clone(), filter.clone()).await;
        }));
    }

    for tsk in join {
        tsk.await.unwrap();
    }

    Ok(())
}

async fn split_pcap(path: Arc<String>, filter: Arc<String>) {
    let file_path = Path::new(path.as_str());
    if file_path.is_file() {
        let mut pcap_file = Capture::from_file(&file_path)
            .expect(format!("Unable to open pcap file: {}", path).as_str());
        if !filter.is_empty() {
            pcap_file
                .filter(filter.as_str())
                .expect("Invalid BPF filter!");
        }
        let out_dir = Path::new("./output");
        if !out_dir.is_dir() {
            fs::create_dir(out_dir)
                .await
                .expect("Unable to create output directory");
        }
        let mut count: u64 = 0;
        let base = path.split("/").last().unwrap();
        while let Ok(pkt) = pcap_file.next() {
            count += 1;
            let n = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time error");
            let mut new_file = File::create(format!(
                "{}/{}_{}_{}.bin",
                out_dir.to_str().unwrap(),
                n.as_millis(),
                base,
                count
            ))
            .await
            .unwrap();
            new_file.write_all(pkt.data).await.unwrap();
        }
    }
}
