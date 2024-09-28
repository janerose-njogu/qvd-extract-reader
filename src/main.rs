use bitvec::prelude::*;
use bitvec::slice::BitSlice;
use byteorder::{LittleEndian, ReadBytesExt};
use pyo3::{prelude::*, PyErr, exceptions::PyRuntimeError, types::PyDict};
use duckdb::{Connection, Result, types::ToSql}; 
use quick_xml::de::from_str;
use qvd_structure::{QvdFieldHeader, QvdTableHeader};
use std::io::{SeekFrom, Cursor, self, Read, BufReader, ErrorKind};
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::str;
use std::slice::{Chunks,ChunksMut};
use std::{collections::HashMap, fs::File,fs::metadata};
use std::{convert::TryInto, io::prelude::*};
use regex::Regex;
pub mod qvd_structure;

const DEFAULT_CHUNK_SIZE: usize = 2; // Default chunk size for reading data in GB.

fn read_qvd_in_chunks(f: &mut File, offset: usize, chunk_size: usize) -> Result<Vec<u8>, io::Error> {
    f.seek(SeekFrom::Start(offset as u64))?;
    let mut file_reader: BufReader<&mut File> = BufReader::new(f);
    let mut buf: Vec<u8> = vec![0; chunk_size]; 
    
    let bytes_read = file_reader.read(&mut buf)?;
    
    buf.truncate(bytes_read);
    Ok(buf)
}

fn format_convert_to_snake_case(input_string: &str) -> String {
    // Define a regex to match any punctuation symbol
    let re: Regex = Regex::new(r"[^\w\s]").unwrap();
    let cleaned_string = input_string.trim()  // Remove leading and trailing whitespaces
        .replace(" ", "_")  // Replace spaces with underscores
        .replace("-", "_")  // Optionally, replace hyphens with underscores
        .to_lowercase();  // Convert to lowercase
        // Remove punctuation symbols
        re.replace_all(&cleaned_string, "").to_string()
}

fn match_symbols_with_indexes(symbols: &[Option<String>], pointers: &[i64]) -> Vec<Option<String>> {
    let mut cols: Vec<Option<String>> = Vec::new();
    for pointer in pointers.iter() {
        if symbols.is_empty() || *pointer < 0 || *pointer as usize >= symbols.len() {
            // Push None if symbols are empty, pointer is negative, or out of bounds
            cols.push(None);
        } else {
            // Safely clone the symbol if pointer is within bounds
            cols.push(symbols[*pointer as usize].clone());
        }
    }
    cols
}

fn get_symbols_as_strings(buf: &[u8], field: &QvdFieldHeader) -> Vec<Option<String>> {
    let start: usize = field.offset;
    let mut end: usize = start + field.length;
    if start >= buf.len() {
        println!("Start index out of bounds: {} for buffer of length {}", start, buf.len());
    }
    if end > buf.len() {
        end = buf.len();
    }
    let mut strings: Vec<Option<String>> = Vec::new();

    let mut cursor: Cursor<&[u8]> = Cursor::new(&buf[start..end]);
    while cursor.position() < end as u64 {
        let remaining: u64 = (end as u64) - cursor.position();
         if remaining < 1 {
            break; // Not enough data for a full type, exit loop
        }
        let byte = match cursor.read_u8() {
            Ok(b) => b,
            Err(_) => break, // Error in reading, likely due to EOF
        };
         if end > buf.len() {
        end = buf.len();
        }
        println!("field: {}", field.field_name);
        println!("Byte type: {}", byte);

        match byte {
            0 => {
                // Read null-terminated string
                let mut string_bytes = Vec::new();
                loop {
                    if remaining < 1 || cursor.position() >= end as u64 {
                        break; // No more data to read
                    }
                    let next_byte = cursor.read_u8().unwrap_or(0);
                    if next_byte == 0 {
                        break; // Null terminator reached
                    }
                    string_bytes.push(next_byte);
                }
                let value = String::from_utf8(string_bytes).unwrap_or_else(|_| {
                    panic!(
                        "Error parsing string value in field: {}, position: {}",
                        field.field_name,
                        cursor.position()
                    )
                });
                strings.push(Some(value));
            }
            1 => {
                // Check if there's enough data for a 4-byte integer
                if remaining < 4 {
                    break; // Not enough bytes for an integer, exit loop
                }
                let value = cursor.read_i32::<LittleEndian>().unwrap();
                strings.push(Some(value.to_string()));
            }
            2 => {
                // Check if there's enough data for an 8-byte double
                if remaining < 8 {
                    break; // Not enough bytes for a double, exit loop
                }
                let value = cursor.read_f64::<LittleEndian>().unwrap();
                strings.push(Some(value.to_string()));
            }
            4 => {
                // Read null-terminated string
                let mut string_bytes = Vec::new();
                loop {
                    if remaining < 1 || cursor.position() >= end as u64 {
                        break; // No more data to read
                    }
                    let next_byte = cursor.read_u8().unwrap_or(0);
                    if next_byte == 0 {
                        break; // Null terminator reached
                    }
                    string_bytes.push(next_byte);
                }
                let value = String::from_utf8(string_bytes).unwrap_or_else(|_| {
                    panic!(
                        "Error parsing string value in field: {}, position: {}",
                        field.field_name,
                        cursor.position()
                    )
                });
                strings.push(Some(value));
            }
            5 => {
                // Check if there's enough data to skip 4 bytes
                if remaining < 4 {
                    break; // Not enough bytes, exit loop
                }
                cursor.seek(SeekFrom::Current(4)).unwrap(); // Skip 4 bytes
                let mut string_bytes = Vec::new();
                loop {
                    if remaining < 1 || cursor.position() >= end as u64 {
                        break; // No more data to read
                    }
                    let next_byte = cursor.read_u8().unwrap_or(0);
                    if next_byte == 0 {
                        break; // Null terminator reached
                    }
                    string_bytes.push(next_byte);
                }
                let value = String::from_utf8(string_bytes).unwrap_or_else(|_| {
                    panic!(
                        "Error parsing string value in field: {}, position: {}",
                        field.field_name,
                        cursor.position()
                    )
                });
                strings.push(Some(value));
            }
            6 => {
                // Check if there's enough data to skip 8 bytes
                if remaining < 8 {
                    break; // Not enough bytes, exit loop
                }
                cursor.seek(SeekFrom::Current(8)).unwrap(); // Skip 8 bytes
                let mut string_bytes = Vec::new();
                loop {
                    if remaining < 1 || cursor.position() >= end as u64 {
                        break; // No more data to read
                    }
                    let next_byte = cursor.read_u8().unwrap_or(0);
                    if next_byte == 0 {
                        break; // Null terminator reached
                    }
                    string_bytes.push(next_byte);
                }
                let value = String::from_utf8(string_bytes).unwrap_or_else(|_| {
                    panic!(
                        "Error parsing string value in field: {}, position: {}",
                        field.field_name,
                        cursor.position()
                    )
                });
                strings.push(Some(value));
            }
            _ => {
                // Handle unexpected bytes gracefully by skipping unknown types
                println!("Unknown byte type: {}", byte);
            }
        }
    }
    strings
}

fn get_row_indexes(buf: &[u8], field: &QvdFieldHeader, record_byte_size: usize) -> Vec<i64> {
    // Retrieve bit stuffed data. Each row has index to value from symbol map.
    let mut cloned_buf: Vec<u8> = buf.to_owned();
    let chunks: ChunksMut<'_, u8> = cloned_buf.chunks_mut(record_byte_size);
    let mut indexes: Vec<i64> = Vec::new();
    for chunk in chunks {
        // Reverse the bytes in the record
        chunk.reverse();
        let bits: &BitSlice<Msb0, u8> = BitSlice::<Msb0, _>::from_slice(&chunk[..]).unwrap();
        let len: usize = bits.len();
        let start: usize = len.checked_sub(field.bit_offset).unwrap_or(0);
        let end: usize = start.checked_sub(field.bit_width).unwrap_or(0);
        if start <= end || end >= len {
            // Skip this chunk if indices are out of bounds
            continue;
        }
        let binary: Vec<u8> = bitslice_to_vec(&bits[end..start]);
        let index: u32 = binary_to_u32(binary);
        indexes.push((index as i32 + field.bias) as i64);
    }
    indexes
}

// Slow
fn binary_to_u32(binary: Vec<u8>) -> u32 {
    let mut sum: u32 = 0;
    for bit in binary {
        sum <<= 1;
        sum += bit as u32;
    }
    sum
}

// Slow
fn bitslice_to_vec(bitslice: &BitSlice<Msb0, u8>) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for bit in bitslice {
        let val: u8 = match bit {
            true => 1,
            false => 0,
        };
        v.push(val);
    }
    v
}

fn get_xml_data(qvd_file_path: &str) -> Result<String, io::Error> {
    match read_file(qvd_file_path) {
        Ok(mut reader) => {
            let mut buffer = Vec::new();
            // There is a line break, carriage return and a null terminator between the XMl and data
            // Find the null terminator
            reader
                .read_until(0, &mut buffer)
                .expect("Failed to read file");
            let xml_string: &str =
                str::from_utf8(&buffer[..]).expect("xml section contains invalid UTF-8 chars");
            Ok(xml_string.to_owned())
        }
        Err(e) => Err(e),
    }
}

fn read_file<P>(filename: P) -> io::Result<io::BufReader<File>>
where
    P: AsRef<Path>,
{
    let file: File = File::open(filename)?;
    Ok(io::BufReader::new(file))
}

fn main() -> std::io::Result<()> {
    let qvd_file_path: &str = r"C:\Users\LENOVO\Documents\Client Projects\USC Keck\extracts\Orders_Restraint_All.qvd";
    let chunk_size: Option<usize> =Some(2);
    let chunk_size_in_bytes: usize = if chunk_size.unwrap_or(0) > 0 {
        chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE) * 1024 * 1024
    } else {
        DEFAULT_CHUNK_SIZE * 1024 * 1024
    };

    let xml_data: String = get_xml_data(&qvd_file_path).expect("Error reading file");
    let qvd_structure: QvdTableHeader = from_str(&xml_data).unwrap(); 

    let mut binary_section_offset: usize = xml_data.as_bytes().len();
    let mut symbol_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
    
    // Acquire Python interpreter context
    Python::with_gil(|py: Python<'_>| {
    let dict: &PyDict = PyDict::new(py);
    // CREATE TABLE IN DUCKDB
    let duck_db_conn: Connection = Connection::open("extract_qvd.db").expect("Error connecting to DuckDB database");

    let formatted_table_name: String = format_convert_to_snake_case(&qvd_structure.table_name);
    let mut create_table_query = format!("CREATE TABLE IF NOT EXISTS {} (", formatted_table_name);

    let column_names: Vec<String> = qvd_structure.fields.headers.iter().map(|field: &QvdFieldHeader| format_convert_to_snake_case(&field.field_name)).collect();
    let column_count: &usize = &column_names.len();
    for field in &column_names {
        create_table_query.push_str(&format!("{} TEXT,", format_convert_to_snake_case(&field)));
    }
    create_table_query.pop(); // Remove trailing comma
    create_table_query.push_str(");");

    duck_db_conn.execute(&create_table_query, []).expect("Error creating table");
    if let Ok(mut f) = File::open(&qvd_file_path) {
        while let Ok(data_chunk) = read_qvd_in_chunks(&mut f, binary_section_offset, chunk_size_in_bytes) {
            // let data_chunk: Vec<u8> = read_qvd_in_chunks(&mut f, binary_section_offset, lines_to_read)?;
            println!("Chunk size: {}", data_chunk.len());
            if data_chunk.is_empty(){
                    break;
            }
            let record_byte_size: usize = qvd_structure.record_byte_size;
            let placeholders: Vec<String> = column_names.iter().map(|_| "?".to_string()).collect();
            let insert_query = format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    formatted_table_name,
                    column_names.join(", "),
                    placeholders.join(", ")
            );
            for field in &qvd_structure.fields.headers {
                symbol_map.insert(
                        field.field_name.clone(),
                        get_symbols_as_strings(&data_chunk, &field),
                );

                    // let symbol_indexes: Vec<i64> = get_row_indexes(&data_chunk, &field, record_byte_size);
                    // let column_values: Vec<Option<String>> = match_symbols_with_indexes(&symbol_map[&field.field_name], &symbol_indexes);
                    // let record_count: usize = column_values.len();
                    // println!("No of records: {}", record_count);
                    // for record_index in 0..record_count {
                        // records to be inserted in duck db
                        // let mut row_values:  Vec<&(dyn ToSql + 'static)> = Vec::new();
                        
                // //         // For each column, get the value at the current row index
                // //         for i in 0..column_count  {
                // //             let value: &(dyn ToSql + 'static) = match &column_values[i] {
                // //                 Some(val) => Box::leak(Box::new(val.clone())),
                // //                 None => Box::leak(Box::new(String::new())),
                // //             };
                // //             row_values.push(value);
                // //         }
                // //         // Execute the insert query for each row
                // //         duck_db_conn.execute(&insert_query, &row_values[..])?;
                //     }
            }
            binary_section_offset += chunk_size_in_bytes; // Move offset for the next chunk
        }
    }
    Ok(())
})
}