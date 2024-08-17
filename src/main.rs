use std::{env, fs};
use std::fs::metadata;
use std::io::prelude::*;
use std::io;
use std::path::Path;
use log::{info, warn, error, debug, trace};
use env_logger;

const MAX_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const DECRYPT_EXTENSION: &str = "ohqrughfubsw";
const DECRYPT_FIXX: &str = "000";
const FAKE_ENCRYPTED_HEADER: [u8; 16] = [0x62, 0x14, 0x23, 0x64, 0x3f, 0x00, 0x13, 0x01,
    0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a];


fn add_header(dest: &str) -> std::io::Result<()> {
    let file_open = fs::OpenOptions::new().write(true).create(true).open(dest);
    if let Ok(mut write_stream) = file_open {
        write_stream.write(&FAKE_ENCRYPTED_HEADER)?;
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Error occurred when opening write file."))
    }
}

fn safe_delete(src: &str) -> std::io::Result<()> {
    if Path::new(src).exists() {
        match fs::remove_file(src) {
            Ok(_) => debug!("File '{}' deleted successfully.", src),
            Err(e) => error!("Failed to delete file '{}': {}", src, e),
        }
    } else {
        debug!("File '{}' does not exist.", src);
    }
    Ok(())
}

fn save_as(src: &str, dest: &str) -> std::io::Result<()> {
    let metadata = metadata(src)?;
    let mut buffer_size: usize = metadata.len() as usize;
    if buffer_size > MAX_BUFFER_SIZE {
        buffer_size = MAX_BUFFER_SIZE;
    }
    let file_open = fs::File::open(src);
    if let Ok(mut read_stream) = file_open {
        // let mut write_stream = fs::OpenOptions::new().append(true).create(true).open(dest)?;
        if let Ok(mut write_stream) = fs::OpenOptions::new().append(true).create(true).open(dest)
        {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                let bytes_read = read_stream.read(&mut buffer)?;
                if bytes_read == 0 {
                    debug!("End of file. {}", src);
                    break Ok(());
                }
                write_stream.write(&buffer[..bytes_read])?;
            }
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Error occurred when opening write file."))
        }
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Error occurred when opening read file."))
    }
}

fn is_encrypted(src: &str) -> bool {
    let file_open = fs::File::open(src);
    if let Ok(mut read_stream) = file_open {
        let mut buffer = [0u8; 4];
        let bytes_read = read_stream.read(&mut buffer).unwrap();
        if bytes_read == 4 {
            if buffer == [0x62, 0x14, 0x23, 0x65] || buffer == [0x77, 0x14, 0x23, 0x65] {
                return true;
            }
        }
    }
    false
}


fn has_file_with_extension(dir: &Path, extension: &str) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // 检查是否为文件，并且后缀名与给定的后缀名匹配
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == extension {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn rename_file(src: &str, dest: &str) -> io::Result<()> {
    safe_delete(&dest)?;
    debug!("Renaming file from {} to {}", src, dest);
    fs::rename(src, dest)
}

fn copy_file(src: &str, dest: &str) -> io::Result<()> {
    safe_delete(&dest)?;
    debug!("Copying file from {} to {}", src, dest);
    fs::copy(src, dest).expect("Copy failed");
    Ok(())
}

fn rename_file_to_c(src: &str) -> io::Result<(String)> {
    let dest = format!("{}.c", src);
    rename_file(src, &dest).expect("Rename failed.");
    Ok(dest)
}

fn copy_file_to_c(src: &str) -> io::Result<(String)> {
    let dest = format!("{}.c", src);
    copy_file(src, &dest).expect("Copy failed.");
    Ok(dest)
}

enum DecryptMode {
    FileNameSuffix,
    FileNamePrefix,
    FileHeader,
    FileNameSuffixAndPrefix,
    Raw,
}


fn ask_decrypt_mode() -> DecryptMode {
    println!("Please select decrypt mode(5.Raw by default):");
    println!("1. File name suffix");
    println!("2. File name prefix");
    println!("3. File name suffix and prefix");
    println!("4. File header");
    println!("5. Raw");
    let mut mode = String::new();
    print!(">   ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut mode).expect("Failed to read line.");
    match mode.trim() {
        "1" => {
            println!("Selected mode: File name suffix");
            DecryptMode::FileNameSuffix
        }
        "2" => {
            println!("Selected mode: File name prefix");
            DecryptMode::FileNamePrefix
        }
        "3" => {
            println!("Selected mode: File name suffix and prefix");
            DecryptMode::FileNameSuffixAndPrefix
        }
        "4" => {
            println!("Selected mode: File header");
            DecryptMode::FileHeader
        }
        _ => {
            println!("Selected mode: Raw");
            DecryptMode::Raw
        }
    }
}

fn quick_decrypt_mode(targets: &[String]) -> io::Result<()> {
    let mode = ask_decrypt_mode();
    for target in targets {
        let c_file_name = copy_file_to_c(target)?;
        match mode {
            DecryptMode::FileNameSuffix => {
                let dest_file_path = format!("{}.{}", &target, DECRYPT_FIXX);
                safe_delete(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path)?;
            }
            DecryptMode::FileNamePrefix => {
                let target_file_path = Path::new(target);
                let dest_file_path =
                    if let Some(file_name) = target_file_path.file_name() {
                        let file_name = file_name.to_str().unwrap();
                        let dest_file_name = format!("{}-{}", DECRYPT_FIXX, file_name);
                        let _dest_file_path = target_file_path.with_file_name(dest_file_name);
                        _dest_file_path.to_string_lossy().into_owned()
                    } else {
                        warn!("Failed to get file name from path: {}", target);
                        let _dest_file_path = target_file_path.to_path_buf();
                        _dest_file_path.to_string_lossy().into_owned()
                    };
                safe_delete(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path)?;
            }
            DecryptMode::FileNameSuffixAndPrefix => {
                let target_file_path = Path::new(target);
                let dest_file_path =
                    if let Some(file_name) = target_file_path.file_name() {
                        let file_name = file_name.to_str().unwrap();
                        let dest_file_name = format!("{}-{}.{}", DECRYPT_FIXX, file_name, DECRYPT_FIXX);
                        let _dest_file_path = target_file_path.with_file_name(dest_file_name);
                        _dest_file_path.to_string_lossy().into_owned()
                    } else {
                        warn!("Failed to get file name from path: {}", target);
                        let _dest_file_path = target_file_path.to_path_buf();
                        _dest_file_path.to_string_lossy().into_owned()
                    };
                safe_delete(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path)?;
            }
            DecryptMode::FileHeader => {
                let dest_file_path = target.clone();
                safe_delete(&dest_file_path)?;
                add_header(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path)?;
            }
            DecryptMode::Raw => {
                let dest_file_path = target.clone();
                safe_delete(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path)?;
            }
        }
        safe_delete(&c_file_name)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        println!("Arguments got, entering quick decrypt mode.");
        quick_decrypt_mode(&args[1..])?;
        return Ok(());
    }
    let current_dir = env::current_dir()?;
    info!("Current directory: {:?}", current_dir);
    if has_file_with_extension(&current_dir, DECRYPT_EXTENSION)? {
        println!("Found decrypted file, entering unpack mode.");
    } else {
        println!("Entering decrypt mode.");
    }
    Ok(())
}