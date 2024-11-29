use bitvec::prelude::*;
use memmap2::{MmapOptions, Mmap};
use pyo3::{prelude::*, types::PyDict, wrap_pyfunction};
use quick_xml::de::from_str;
use qvd_structure::{QvdFieldHeader, QvdTableHeader};
use regex::Regex;
use std::io::{self, BufReader, Read, SeekFrom};
use std::path::Path;
use std::str;
use std::{collections::HashMap, fs::File};
use std::{convert::TryInto, io::prelude::*};
pub mod qvd_structure;

const DEFAULT_CHUNK_SIZE: usize = 2; // the default chunk size to read

fn format_convert_to_snake_case(input_string: &str) -> String {
    // Define a regex to match any punctuation symbol
    let re: Regex = Regex::new(r"[^\w\s]").unwrap();
    let cleaned_string: String = input_string.trim()  // Remove leading and trailing whitespaces
        .replace(" ", "_")  // Replace spaces with underscores
        .replace("-", "_")  // Optionally, replace hyphens with underscores
        .to_lowercase();  // Convert to lowercase
        // Remove punctuation symbols
        re.replace_all(&cleaned_string, "").to_string()
}

fn read_qvd_to_buf(mut f: File, offset: usize, chunk_size: usize) -> Vec<u8> {
        let mut reader: BufReader<&_> = BufReader::new(&f);
        reader.seek(SeekFrom::Start(offset as u64));
        let mut buf: Vec<u8> = Vec::new();
        let bytes_read: usize = reader.read(&mut buf).unwrap();
        buf.truncate(bytes_read);
        buf
}

fn match_symbols_with_indexes(symbols: &[Option<String>], pointers: &[i64]) -> Vec<Option<String>> {
    let mut cols: Vec<Option<String>> = Vec::new();
    for pointer in pointers.iter() {
        if symbols.is_empty() || *pointer < 0 || (*pointer as usize) >= symbols.len() {
            // Check if the pointer is out of bounds
            cols.push(None);
        } else {
            cols.push(symbols[*pointer as usize].clone());
        }
    }
    cols
}

fn get_symbols_as_strings(buf: &[u8], field: &QvdFieldHeader) -> Vec<Option<String>> {
    let start: usize = field.offset;
    let end: usize = start + field.length;
    let mut string_start: usize = 0;
    let mut strings: Vec<Option<String>> = Vec::new();

    let mut i: usize = start;
    while i < end {
        let byte: &u8 = &buf[i];
        // Check first byte of symbol. This is not part of the symbol but tells us what type of data to read.
        match byte {
            0 => {
                // Strings are null terminated
                // Read bytes from start fo string (string_start) up to current byte.
                let utf8_bytes: Vec<u8> = buf[string_start..i].to_vec();
                let value: String = String::from_utf8_lossy(&utf8_bytes).to_string();
                strings.push(Some(value));
                i += 1;
            }
            1 => {
                // 4 byte integer
                let target_bytes: Vec<u8> = buf[i + 1..i + 5].to_vec();
                let byte_array: [u8; 4] = target_bytes.try_into().unwrap();
                let numeric_value: i32 = i32::from_le_bytes(byte_array);
                strings.push(Some(numeric_value.to_string()));
                i += 5;
            }
            2 => {
                // 4 byte double
                let target_bytes: Vec<u8> = buf[i + 1..i + 9].to_vec();
                let byte_array: [u8; 8] = target_bytes.try_into().unwrap();
                let numeric_value = f64::from_le_bytes(byte_array);
                strings.push(Some(numeric_value.to_string()));
                i += 9;
            }
            4 => {
                // Beginning of a null terminated string type
                // Mark where string value starts, excluding preceding byte 0x04
                i += 1;
                string_start = i;
            }
            5 => {
                // 4 bytes of unknown followed by null terminated string
                // Skip the 4 bytes before string
                i += 5;
                string_start = i;
            }
            6 => {
                // 8 bytes of unknown followed by null terminated string
                // Skip the 8 bytes before string
                i += 9;
                string_start = i;
            }
            _ => {
                // Part of a string, do nothing until null terminator
                i += 1;
            }
        }
    }
    strings
}

fn get_row_indexes(buf: &[u8], field: &QvdFieldHeader, record_byte_size: usize) -> Vec<i64> {
    let mut cloned_buf: Vec<u8> = buf.to_owned();
    let chunks: std::slice::ChunksMut<'_, u8> = cloned_buf.chunks_mut(record_byte_size);
    let mut indexes: Vec<i64> = Vec::new();

    for chunk in chunks {
        chunk.reverse();       
        let bits: &BitSlice<Msb0, u8> = BitSlice::<Msb0, _>::from_slice(&chunk[..]).unwrap();    
        if field.bit_offset <= bits.len() {
            let start: usize = bits.len() - field.bit_offset;
            if field.bit_width <= start {
                let end: usize = start - field.bit_width;

                let binary: Vec<u8> = bitslice_to_vec(&bits[end..start]);
                let index: u32 = binary_to_u32(binary);

                indexes.push((index as i32 + field.bias) as i64);
            } else {
                eprintln!(
                    "Warning: field.bit_width ({}) is too large for start value ({})",
                    field.bit_width, start
                );
                indexes.push(-1);
            }
        } else {
            eprintln!(
                "Warning: field.bit_offset ({}) is out of range for bits.len() ({})",
                field.bit_offset, bits.len()
            );
            indexes.push(-1);
        }
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
        let val = match bit {
            true => 1,
            false => 0,
        };
        v.push(val);
    }
    v
}

fn get_xml_data(file_name: &str) -> Result<String, io::Error> {
    match read_file(file_name) {
        Ok(mut reader) => {
            let mut buffer: Vec<u8> = Vec::new();
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
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file))
}

fn main() -> std::io::Result<()> {
    let qvd_file_path: &str = r"C:\Users\LENOVO\Documents\Client Projects\USC Keck\extracts\Orders_Restraint_All.qvd";
    // r"C:\Users\LENOVO\Documents\Client Projects\USC Keck\extracts\Medication.qvd";//23minutes
    // r"C:\Users\LENOVO\Documents\Client Projects\USC Keck\extracts\Encounter_Personnel.qvd"; 7minutes
    // r"C:\Users\LENOVO\Documents\Client Projects\USC Keck\extracts\Orders_Restraint_All.qvd";
    let chunk_size: Option<usize> = Some(0);
    let chunk_size_in_bytes: usize = if chunk_size.unwrap_or(0) > 0 {
        chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE) * 1024
    } else {
        DEFAULT_CHUNK_SIZE * 1024
    };
    println!("Chunk size in bytes: {}", chunk_size_in_bytes);
    
    let xml_metadata: String = get_xml_data(&qvd_file_path).expect("Error reading file");
    let qvd_structure: QvdTableHeader = from_str(&xml_metadata).unwrap(); 
    
    let binary_section_offset: usize = xml_metadata.as_bytes().len();
    let mut symbol_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
    
    // let duck_db_conn: Connection = Connection::open("extract_qvd.db").expect("Error connecting to DuckDB database");
    
    let formatted_table_name: String = format_convert_to_snake_case(&qvd_structure.table_name);
    let mut create_table_query: String = format!("CREATE TABLE IF NOT EXISTS {} (", formatted_table_name);

    println!("table name: {}", formatted_table_name);
    
    let row_count: u32 = qvd_structure.no_of_records;
    println!("row count: {}", row_count);
    
    let mut qvd_fields: Vec<QvdFieldHeader> = qvd_structure.fields.headers;
    let column_names: Vec<String> = qvd_fields.iter().map(|field: &QvdFieldHeader| format_convert_to_snake_case(&field.field_name)).collect();
    
    let column_count: usize = column_names.len();
    println!("field count: {}", column_count);
    
    for field in &column_names {
        create_table_query.push_str(&format!("{} TEXT,", format_convert_to_snake_case(&field)));
    }
    create_table_query.pop(); // Remove trailing comma
    create_table_query.push_str(");");

    // duck_db_conn.execute(&create_table_query, []).expect("Error creating table");
    
    if let Ok(mut f) = File::open(&qvd_file_path) {
        let mmap: Mmap = unsafe { MmapOptions::new().map(&f).unwrap() };
        let record_byte_size: usize = qvd_structure.record_byte_size;
        let placeholders: Vec<String> = column_names.iter().map(|_| "?".to_string()).collect();
        let insert_query: String = format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    formatted_table_name,
                    column_names.join(", "),
                    placeholders.join(", ")
            );
        let mut offset: usize = binary_section_offset;
        let buf: &[u8] = &mmap;
        // let buf: Vec<u8> = read_qvd_to_buf(f.try_clone().unwrap(), offset, offset);
        println!("Buffer Length: {}", buf.len());
        
        let rows_start: usize = qvd_structure.offset;
        let rows_end: usize = buf.len();
        let rows_section: &[u8] = &buf[rows_start..rows_end];
        let record_byte_size: usize = qvd_structure.record_byte_size;

        for field in &qvd_fields {
            symbol_map.insert(
                    field.field_name.clone(),
                    get_symbols_as_strings(&buf, &field),
                );
            let symbol_indexes: Vec<i64> = get_row_indexes(&rows_section, &field, record_byte_size);
            let column_values: Vec<Option<String>> = match_symbols_with_indexes(&symbol_map[&field.field_name], &symbol_indexes);
            // println!("Column Values: {}",column_values.len());
            for (index, value) in column_values.iter().enumerate() {
                match value {
                    Some(val) => println!("Column {}: {}", index + 1, val),
                    None => println!("Column {}: None", index + 1),
                }
            }
            }
        }
    Ok(())
}
#[cfg(test)]
mod tests {
}