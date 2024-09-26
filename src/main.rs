use std::{env, fs};
use std::collections::VecDeque;
use std::fs::metadata;
use std::io::prelude::*;
use std::io;
use std::str;
use std::path::Path;
use log::{info, warn, error, debug, trace};
use env_logger;
use base64::prelude::*;
use std::process::Command;
// extern crate rand;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;


mod big_json;

use big_json::big_json_write::{BigJsonWrite, BracketType};


const MAX_BUFFER_SIZE: usize = 8 * 1024 * 1024;
/// base64 set 3 bytes as a group
const B64_BUFFER_SIZE: usize = MAX_BUFFER_SIZE / 3 * 3;
const READ_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const RB64_BUFFER_SIZE: usize = READ_BUFFER_SIZE / 4 / 4 * 4;

const DECRYPT_EXT_SUFIXX: &str = "ohqrughfubsw";
const DECRYPT_FIXX: &str = "000";
const FAKE_ENCRYPTED_HEADER: [u8; 16] = [0x62, 0x14, 0x23, 0x65, 0x3f, 0x00, 0x13, 0x01,
    0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d, 0x0a];


fn ran_str(length: usize) -> String {
    let mut rng = thread_rng();
    let random_string: String = (0..length)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();
    random_string
}

fn add_header(dest: &str) -> io::Result<()> {
    if let Some(parent_dir) = Path::new(dest).parent() {
        fs::create_dir_all(parent_dir)?;
    }
    let file_open = fs::OpenOptions::new().write(true).create(true).open(dest);
    if let Ok(mut write_stream) = file_open {
        write_stream.write(&FAKE_ENCRYPTED_HEADER)?;
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Error occurred when adding header."))
    }
}

fn safe_delete(src: &str) -> io::Result<()> {
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

fn append_to_file(dest: &str, content: &str) -> io::Result<()> {
    let file_open = fs::OpenOptions::new().append(true).create(true).open(dest);
    if let Ok(mut write_stream) = file_open {
        write_stream.write(content.as_bytes())?;
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Error occurred when opening write file."))
    }
}

fn save_as(src: &str, dest: &str, base64: &bool) -> io::Result<()> {
    let metadata = metadata(src)?;
    let mut buffer_size: usize = metadata.len() as usize;
    if buffer_size > if *base64 { B64_BUFFER_SIZE } else { MAX_BUFFER_SIZE } {
        buffer_size = if *base64 { B64_BUFFER_SIZE } else { MAX_BUFFER_SIZE };
    }
    let file_open = fs::File::open(src);
    if let Ok(mut read_stream) = file_open {
        // let mut write_stream = fs::OpenOptions::new().append(true).create(true).open(dest)?;
        if let Ok(mut write_stream) = fs::OpenOptions::new().append(true).create(true).open(dest)
        {
            let mut buffer = vec![0u8; buffer_size];
            // let mut count = 0;
            loop {
                let bytes_read = read_stream.read(&mut buffer)?;
                if bytes_read == 0 {
                    if *base64 {
                        write_stream.write("$".as_bytes())?;
                    }
                    debug!("End of file. {}", src);
                    break Ok(());
                }
                // if count == 0{
                //     println!("{:?}", &buffer[..32]);
                //     count += 1;
                // }
                if *base64 {
                    // let encoded: Vec<u8> = BASE64_STANDARD.encode(&buffer[..bytes_read]).into_bytes();
                    let encoded = BASE64_STANDARD.encode(&buffer[..bytes_read]).into_bytes();
                    write_stream.write(&encoded)?;
                } else {
                    write_stream.write(&buffer[..bytes_read])?;
                }
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Error occurred when opening write file."))
        }
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Error occurred when opening read file."))
    }
}

// fn is_encrypted(src: &str) -> bool {
//     let file_open = fs::File::open(src);
//     if let Ok(mut read_stream) = file_open {
//         let mut buffer = [0u8; 4];
//         let bytes_read = read_stream.read(&mut buffer).unwrap();
//         if bytes_read == 4 {
//             if buffer == [0x62, 0x14, 0x23, 0x65] || buffer == [0x77, 0x14, 0x23, 0x65] {
//                 return true;
//             }
//         }
//     }
//     false
// }


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

fn find_file_with_extension(dir: &Path, extension: &str) -> io::Result<String> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == extension {
                    return Ok(Some(path.to_string_lossy().into_owned()).unwrap());
                }
            }
        }
    }
    Ok("".parse().unwrap())
}

fn rename_file(src: &str, dest: &str) -> io::Result<()> {
    safe_delete(&dest)?;
    debug!("Renaming file from {} to {}", src, dest);
    fs::rename(src, dest)
}

fn copy_file(src: &str, dest: &str) -> io::Result<()> {
    safe_delete(&dest)?;
    debug!("Copying file from {} to {}", src, dest);
    // fs::copy(src, dest).expect("Copy failed");
    /**
    ***   use external copy, don't know why
    ***   guess that internal copy may not close file properly
    ***   or the delay is too short to get re-hooked.
    **/
    // let cmd_str = format!("copy \"{}\" \"{}\"", src, dest).to_string();
    let cmd_str = format!("echo f | xcopy /hy {} {}", src, dest).to_string();
    // println!("cmd_str: {}", cmd_str);
    Command::new("cmd").arg("/c").arg(cmd_str).output().expect("cmd exec error!");
    Ok(())
}

fn rename_file_to_c(src: &str) -> io::Result<(String)> {
    let dest = format!("{}.c", src);
    rename_file(src, &dest).expect("Rename failed.");
    Ok(dest)
}

fn check_is_encrypted(src: &str) -> bool {
    let file_open = fs::File::open(src);
    if let Ok(mut read_stream) = file_open {
        let mut buffer = [0u8; 4];
        let bytes_read = read_stream.read(&mut buffer).unwrap();
        if bytes_read == 4 {
            if buffer == FAKE_ENCRYPTED_HEADER[0..4] {
                return true;
            }
        }
    }
    false
}

fn copy_file_to_c(src: &str) -> io::Result<(String)> {
    if check_is_encrypted(src) {
        let dest = format!("{}.c", src);
        copy_file(src, &dest).expect("Copy failed.");
        Ok(dest.clone())
    } else {
        let dest = src.to_owned();
        Ok(dest.clone())
    }
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

fn file_name_with_space(src: &str) -> bool {
    let path = Path::new(src);
    if let Some(file_name) = path.file_name() {
        let file_name = file_name.to_str().unwrap();
        if file_name.contains(" ") {
            return true;
        }
    }
    false
}

fn file_exist(x: &String) -> bool {
    if Path::new(x).exists() {
        return true;
    }
    false
}

fn quick_decrypt_mode(targets: &[String]) -> io::Result<()> {
    let mode = ask_decrypt_mode();
    for target in targets {
        if file_name_with_space(target) {
            warn!("File name contains space, please rename it before decrypting.");
            continue;
        }
        let c_file_name = copy_file_to_c(target)?;
        if !file_exist(&c_file_name) {
            println!("Somehow file not exist: {}", c_file_name);
            continue;
        }
        match mode {
            DecryptMode::FileNameSuffix => {
                let dest_file_path = format!("{}.{}", &target, DECRYPT_FIXX);
                safe_delete(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path, &false)?;
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
                save_as(&*c_file_name, &*dest_file_path, &false)?;
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
                save_as(&*c_file_name, &*dest_file_path, &false)?;
            }
            DecryptMode::FileHeader => {
                let dest_file_path = target.clone();
                safe_delete(&dest_file_path)?;
                add_header(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path, &false)?;
            }
            DecryptMode::Raw => {
                let dest_file_path = target.clone();
                safe_delete(&dest_file_path)?;
                save_as(&*c_file_name, &*dest_file_path, &false)?;
            }
        }
        if !are_same_file(&c_file_name.to_string(), target)?{
            safe_delete(&c_file_name)?;
        }
    }
    Ok(())
}

// fn recursive_decrypt(father_path: Box<Path>, json_cache: &mut BigJsonWrite) -> io::Result<()> {
//     for entry in fs::read_dir(father_path)? {
//         let entry = entry?;
//         let path = entry.path();
//         if path.is_file() {
//             info!("File: {:?}", path);
//             json_cache.push(&BracketType::Dict);
//             json_cache.add_short_content("\"type\": \"file\",");
//
//
//         } else if path.is_dir() {
//             info!("Dir: {:?}", path);
//             recursive_decrypt(Box::from(path), json_cache).expect("recurse failed");
//         }
//     }
//     Ok(())
// }
//
// fn decrypt_mode() -> io::Result<()> {
//     let current_dir = env::current_dir()?;
//     println!("Current directory: {:?}", current_dir);
//     let mut target = current_dir.clone();
//     target.push(ran_str(16).as_str());
//     let mut obj_json = BigJsonWrite::new(
//         &target.with_extension(DECRYPT_EXTENSION)
//     );
//     obj_json.init();
//     obj_json.push(&BracketType::List);
//     recursive_decrypt(Box::from(current_dir), &obj_json)?;
//     obj_json.pop();
//     Ok(())
// }

fn are_same_file(path1: &str, path2: &str) -> io::Result<bool> {
    let canonical_path1 = fs::canonicalize(path1)?;
    let canonical_path2 = fs::canonicalize(path2)?;
    // println!("Canonical path1: {:?}", canonical_path1);
    // println!("Canonical path2: {:?}", canonical_path2);
    Ok(canonical_path1 == canonical_path2)
}

fn recursive_decrypt(father_path: &Box<Path>, proc_path: &Box<Path>, target: &Box<Path>) -> io::Result<()> {
    let current_exe_path = env::current_exe()?;
    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            info!("File: {:?}", path);
            let rev_path = path.strip_prefix(father_path).unwrap();
            if are_same_file(current_exe_path.to_str().unwrap(), path.to_str().unwrap())? {
                continue;
            }
            println!("Packing: {:?}", path);
            // if file_name_with_space(path.to_str().unwrap()) {
            //     warn!("File name contains space, please rename it before decrypting.");
            //     continue;
            // }
            let c_file_name = copy_file_to_c(path.to_str().unwrap())?;
            if !file_exist(&c_file_name) {
                println!("Somehow file not exist: {}", c_file_name);
                continue;
            }
            append_to_file(&*target.to_string_lossy(),
                           &(BASE64_STANDARD.encode(&*rev_path.to_string_lossy()) + "$"))?;
            save_as(&*c_file_name, &target.to_string_lossy(), &true)?;
            if c_file_name != path.to_str().unwrap(){
                safe_delete(&c_file_name)?;
            }
        } else if path.is_dir() {
            info!("Dir: {:?}", path);
            recursive_decrypt(father_path, &Box::from(path.clone()), target)?
        }
    }
    Ok(())
}

fn decrypt_mode() -> io::Result<()> {
    let current_dir = env::current_dir()?;
    println!("Current directory: {:?}", current_dir);
    let mut target = current_dir.clone();
    target.push(ran_str(16).as_str());
    target.set_extension(DECRYPT_EXT_SUFIXX);
    recursive_decrypt(&Box::from(current_dir.clone()), &Box::from(current_dir.clone()), &Box::from(target.clone()))?;
    Ok(())
}

enum CurrentReading {
    Path,
    Content,
}

fn unpack_mode() -> io::Result<()> {
    fn dump_content(file_path: &str, file_content: &Vec<u8>) -> io::Result<()> {
        let file_content = BASE64_STANDARD.decode(&file_content).unwrap();
        if let Some(parent_dir) = Path::new(file_path).parent() {
            fs::create_dir_all(parent_dir)?;
        }
        if let Ok(mut write_stream) =
            fs::OpenOptions::new().append(true).create(true)
                .open(file_path) {
            write_stream.write(&file_content)?;
        }
        Ok(())
    }

    let mode = ask_decrypt_mode();
    match mode {
        DecryptMode::FileNameSuffix => {
            println!("Unsupported currently");
            return Ok(());
        }
        DecryptMode::FileNamePrefix => {
            println!("Unsupported currently");
            return Ok(());
        }
        DecryptMode::FileNameSuffixAndPrefix => {
            println!("Unsupported currently");
            return Ok(());
        }
        _ => {}
    }

    let current_dir = env::current_dir()?;
    let target = find_file_with_extension(&current_dir, DECRYPT_EXT_SUFIXX)?;
    println!("Unpacking: {:?}", target);
    let file_open = fs::File::open(&target);
    let mut file_path: Vec<u8> = Vec::new();
    let mut file_content: Vec<u8> = Vec::new();
    let mut current_reading = CurrentReading::Path;
    if let Ok(mut read_stream) = file_open {
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let mut proc: VecDeque<u8> = VecDeque::new();
        loop {
            let bytes_read = read_stream.read(&mut buffer)?;
            if bytes_read == 0 {
                debug!("End of file. {}", target);
                break;
            }
            proc.extend(&buffer[..bytes_read]);
            while !proc.is_empty() {
                match current_reading {
                    CurrentReading::Path => {
                        let this_byte = proc.pop_front().unwrap();
                        if this_byte == '$' as u8 {
                            current_reading = CurrentReading::Content;
                            file_path = BASE64_STANDARD.decode(&file_path).unwrap();
                            let mut dec_head = "dec".to_owned() + DECRYPT_EXT_SUFIXX + "\\";
                            let mut dec_head: Vec<u8> = dec_head.as_bytes().to_vec();
                            dec_head.append(&mut file_path);
                            file_path = dec_head;
                            match mode {
                                DecryptMode::FileHeader => {
                                    add_header(str::from_utf8(&file_path).unwrap())?;
                                }
                                _ => {}
                            }
                            println!("Unpacking: {:?}", String::from_utf8(file_path.clone()).unwrap());
                        } else {
                            file_path.push(this_byte);
                        }
                    }
                    CurrentReading::Content => {
                        let this_byte = proc.pop_front().unwrap();
                        if this_byte == '$' as u8 {
                            dump_content(str::from_utf8(&file_path).unwrap(), &file_content)?;
                            file_content.clear();
                            file_path.clear();
                            current_reading = CurrentReading::Path;
                        } else {
                            file_content.push(this_byte);
                            if file_content.len() >= RB64_BUFFER_SIZE {
                                dump_content(str::from_utf8(&file_path).unwrap(), &file_content)?;
                                file_content.clear();
                            }
                        }
                    }
                }
            }
        }
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
    if has_file_with_extension(&current_dir, DECRYPT_EXT_SUFIXX)? {
        println!("Found decrypted file, entering unpack mode.");
        unpack_mode()?;
    } else {
        println!("Entering decrypt mode.");
        decrypt_mode()?;
    }
    Ok(())
}
