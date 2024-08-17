use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use log::{debug, info};

const BUFFER_SIZE: usize = 8 * 1024;

pub enum BracketType {
    List,
    Dict,
    Empty,
}

pub struct BigJsonWrite {
    brackets: Vec<char>,
    pending: Vec<char>,
    buffer: Vec<u8>,
    target: String,
}

impl BigJsonWrite {
    pub(crate) fn new(target_path: &PathBuf) -> Self {
        Self {
            brackets: Vec::new(),
            pending: Vec::new(),
            buffer: Vec::new(),
            target: target_path.to_string_lossy().into_owned(),
        }
    }

    pub fn init(&self) {
        println!("{:?}", self.target);
        BigJsonWrite::safe_delete(&self.target).unwrap();
        if let Ok(mut write_stream) = fs::OpenOptions::new().append(true).create(true).open(&self.target)
        {
            info!("BigJsonWrite initialized.");
        } else {
            panic!("Error occurred when opening write file.");
        }
    }

    fn flush_buffer(&mut self) {
        let mut file = fs::OpenOptions::new().append(true).create(true).open(&self.target).unwrap();
        file.write_all(&*self.buffer).unwrap();
        self.buffer.clear();
    }

    fn check_buffer(&mut self) {
        if self.buffer.len() > 1024 {
            self.flush_buffer();
        }
    }

    fn get_current_bracket(&self) -> BracketType {
        if self.brackets.is_empty() {
            BracketType::Empty
        } else {
            match self.brackets.last().unwrap() {
                '[' => BracketType::List,
                '{' => BracketType::Dict,
                _ => panic!("Invalid bracket type"),
            }
        }
    }

    fn safe_delete(src: &str) -> std::io::Result<()> {
        if Path::new(src).exists() {
            fs::remove_file(src)?;
        }
        Ok(())
    }

    pub fn push(&mut self, push_type: &BracketType) {
        match push_type {
            BracketType::List => {
                self.brackets.push('[');
                self.buffer.push(b'[');
            }
            BracketType::Dict => {
                self.brackets.push('{');
                self.buffer.push(b'{');
            }
            BracketType::Empty => {
                panic!("Invalid bracket type for push");
            }
        }
        self.check_buffer();
    }

    pub fn pop(&mut self) {
        let pop_bracket = self.brackets.pop();
        match pop_bracket {
            Some('[') => {
                self.buffer.push(b']');
            }
            Some('{') => {
                self.buffer.push(b'}');
            }
            _ => panic!("Invalid bracket type for pop"),
        }
        if self.brackets.is_empty() {
            self.flush_buffer();
        } else {
            self.check_buffer();
        }
    }

    pub fn add_short_content(&mut self, content: &str) {
        self.buffer.extend_from_slice(content.as_bytes());
        self.check_buffer();
    }
}