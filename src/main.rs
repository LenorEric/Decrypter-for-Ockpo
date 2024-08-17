use std::fs;
use std::io::prelude::*;

const BUFFER_SIZE: usize = 512 * 1024;

fn save_as(src: &str, dest: &str) {
    let file_open = fs::File::open(src);
    if let Ok(mut read_stream) = file_open {
        let mut write_stream = fs::File::create(dest).unwrap();
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let bytes_read = read_stream.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                println!("End of file.");
                break;
            }
            write_stream.write(&buffer[..bytes_read]).unwrap();
        }
    } else {
        println!("   Error: Error occurred when opening.");
    }
}

fn main() {
    let src = "C:\\Users\\Lenor\\OneDrive\\Desktop\\DocBin\\!Program\\Rust\\Decrypter-for-Ockpo\\content1.txt";
    let dest = "C:\\Users\\Lenor\\OneDrive\\Desktop\\DocBin\\!Program\\Rust\\Decrypter-for-Ockpo\\content2.txt";
    save_as(src, dest);
    println!("File copied successfully.");
}