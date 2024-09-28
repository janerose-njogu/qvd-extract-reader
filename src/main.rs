use bitvec::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::{prelude::*, types::PyDict};
use quick_xml::de::from_str;
use qvd_structure::{QvdFieldHeader, QvdTableHeader};
use regex::Regex;
use std::io::SeekFrom;
use std::io::{self, Read};
use std::path::Path;
use std::str;
use std::{collections::HashMap, fs::File};
use std::{convert::TryInto, io::prelude::*};
pub mod qvd_structure;

const DEFAULT_READ_LINES: usize = 2; // the default number of lines to read

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

fn read_qvd_to_buf<'py>(f: &mut File, binary_section_offset: usize, qvd_fields: &mut Vec<QvdFieldHeader>, py: Python<'py>) -> &'py PyDict {
    let records_to_insert: &PyDict = PyDict::new(py);
    let mut symbol_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
    for field in qvd_fields {
        let total_offset: usize = binary_section_offset + field.offset;
        f.seek(SeekFrom::Start(total_offset as u64)).unwrap();
        let mut buffer: Vec<u8> = vec![0; field.bit_width + 1];
        f.read_exact(&mut buffer).unwrap();
        
        symbol_map.insert(
            field.field_name.clone(),
            get_symbols_as_strings(&buffer, &field),
        );
        // let symbol_indexes: Vec<i64> = get_row_indexes(&rows_section, &field, record_byte_size);
        // let column_values: Vec<Option<String>> =match_symbols_with_indexes(&symbol_map[&field.field_name], &symbol_indexes);
        // Insert the field's value into the dictionary with the field name as the key
        // records_to_insert.set_item(field.field_name.clone(), value).unwrap();
    }
    println!("Symbol Map: {:?}", symbol_map);

    // Return the dictionary with the read data
    records_to_insert
}

fn match_symbols_with_indexes(symbols: &[Option<String>], pointers: &[i64]) -> Vec<Option<String>> {
    let mut cols: Vec<Option<String>> = Vec::new();
    for pointer in pointers.iter() {
        if symbols.is_empty() || *pointer < 0 {
            cols.push(None);
        } else {
            cols.push(symbols[*pointer as usize].clone());
        }
    }
    cols
}

fn get_symbols_as_strings(buf: &[u8], field: &QvdFieldHeader) -> Vec<Option<String>> {
    let mut strings: Vec<Option<String>> = Vec::new();
    
    if buf.len() > 0 {
        // Check first byte of symbol. This is not part of the symbol but tells us what type of data to read.
        let byte: &u8 = &buf[0];
        println!("Buffer: {:?}", buf);
        println!("Byte: {}", byte);
        println!("field: {}", field.field_name);
        
        match byte {
            0 => {
                if let Some(null_pos) = buf.iter().position(|&x| x == 0x00) {
                    // Take the bytes up to the null terminator
                    let utf8_bytes: Vec<u8> = buf[..null_pos].to_vec();
                    
                    // Convert to a UTF-8 string
                    let value: String = String::from_utf8(utf8_bytes).unwrap_or_else(|_| {
                        panic!("Error parsing string value in field: {}", field.field_name)
                    });
                    
                    // Push the resulting string into the `strings` vector
                    strings.push(Some(value));
                } else {
                    // If there's no null byte, handle this as an error or just take the entire buffer
                    let value: String = String::from_utf8(buf.to_vec()).unwrap_or_else(|_| {
                        panic!("Error parsing string value in field: {}", field.field_name)
                    });
                    strings.push(Some(value));
                }
                }
            1 => {
                    // 4 byte integer
                    let mut target_bytes: Vec<u8> = vec![0; 4]; // Initialize a vector to hold 4 bytes
                    if buf.len() >= 5 {
                        // If the buffer has enough bytes, copy the relevant bytes
                        target_bytes.copy_from_slice(&buf[1..5]);
                    } else {
                        // If the buffer is too short, copy available bytes and pad with zeros
                        let bytes_to_copy = buf.len() - 1; // Subtract 1 because we're starting from index 1
                        target_bytes[..bytes_to_copy].copy_from_slice(&buf[1..]); // Copy available bytes
                    }
                    
                    // Now convert to an array
                    let byte_array: [u8; 4] = target_bytes.try_into().unwrap();
                    
                    // Convert to numeric value
                    let numeric_value: i32 = i32::from_le_bytes(byte_array);
                    strings.push(Some(numeric_value.to_string()));
                }
            2 => {
                    // 4 byte double
                    let target_bytes: Vec<u8> = buf[1..9].to_vec();
                    let byte_array: [u8; 8] = target_bytes.try_into().unwrap();
                    let numeric_value: f64 = f64::from_le_bytes(byte_array);
                    strings.push(Some(numeric_value.to_string()));
                    // i += 9;
                }
                4 => {
                    if buf.len() > 1 {
                        // First, check for the active/inactive case
                        if buf[1] == 49 {
                            // Byte 49 is ASCII for '1', meaning active
                            strings.push(Some("1".to_string()));
                        } else if buf[1] == 48 {
                            // Byte 48 is ASCII for '0', meaning inactive
                            strings.push(Some("0".to_string()));
                        } else {
                            // Otherwise, handle as a regular null-terminated string
                            let string_buf: &[u8] = &buf[1..]; // Start after `0x04`
                
                            if let Some(null_pos) = string_buf.iter().position(|&x| x == 0x00) {
                                // Take the bytes up to the null terminator
                                let utf8_bytes: Vec<u8> = string_buf[..null_pos].to_vec();
                                
                                // Convert to a UTF-8 string
                                let value: String = String::from_utf8(utf8_bytes).unwrap_or_else(|_| {
                                    panic!("Error parsing string value in field: {}", field.field_name)
                                });
                                
                                // Push the resulting string into the `strings` vector
                                strings.push(Some(value));
                            } else {
                                // If there's no null byte, handle as a full string
                                let value: String = String::from_utf8(string_buf.to_vec()).unwrap_or_else(|_| {
                                    panic!("Error parsing string value in field: {}", field.field_name)
                                });
                                strings.push(Some(value));
                            }
                        }
                    } else {
                        panic!("Unexpected buffer length for string in field: {}", field.field_name);
                    }
                }            
            5 => {
                    // 4 bytes of unknown followed by null terminated string
                    // Skip the 4 bytes before string
                    // i += 5;
                    // string_start = i;
            }
            6 => {
                    // 8 bytes of unknown followed by null terminated string
                    // Skip the 8 bytes before string
                    // i += 9;
                    // string_start = i;
            }
                _ => {
                    // Part of a string, do nothing until null terminator
                    // i += 1;
            }
         }
    }
    strings
}

// Retrieve bit stuffed data. Each row has index to value from symbol map.
fn get_row_indexes(buf: &[u8], field: &QvdFieldHeader, record_byte_size: usize) -> Vec<i64> {
    let mut cloned_buf = buf.to_owned();
    let chunks = cloned_buf.chunks_mut(record_byte_size);
    let mut indexes: Vec<i64> = Vec::new();
    for chunk in chunks {
        // Reverse the bytes in the record
        chunk.reverse();
        let bits = BitSlice::<Msb0, _>::from_slice(&chunk[..]).unwrap();
        let start = bits.len() - field.bit_offset;
        let end = bits.len() - field.bit_offset - field.bit_width;
        let binary = bitslice_to_vec(&bits[end..start]);
        let index = binary_to_u32(binary);
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
            let mut buffer = Vec::new();
            // There is a line break, carriage return and a null terminator between the XMl and data
            // Find the null terminator
            reader
                .read_until(0, &mut buffer)
                .expect("Failed to read file");
            let xml_string =
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
    let read_lines: Option<usize> =Some(2);
    let no_of_lines_to_read: usize = if read_lines.unwrap_or(0) > 0 {
        read_lines.unwrap_or(DEFAULT_READ_LINES) * 1000
    } else {
        DEFAULT_READ_LINES * 1000
    };
    println!("Lines to read: {}", no_of_lines_to_read);
    
    let xml_metadata: String = get_xml_data(&qvd_file_path).expect("Error reading file");
    let qvd_structure: QvdTableHeader = from_str(&xml_metadata).unwrap(); 
    
    let mut binary_section_offset: usize = xml_metadata.as_bytes().len();
    let mut symbol_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
    
    // Acquire Python interpreter context
    Python::with_gil(|py: Python<'_>| {
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
        let record_byte_size: usize = qvd_structure.record_byte_size;
            let placeholders: Vec<String> = column_names.iter().map(|_| "?".to_string()).collect();
            let insert_query: String = format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    formatted_table_name,
                    column_names.join(", "),
                    placeholders.join(", ")
            );
            let mut inserted_count: u32 = 0;
            while inserted_count < 2 {
                let records_to_insert: &PyDict = read_qvd_to_buf(&mut f, binary_section_offset, &mut qvd_fields, py);
                
                println!("record count: {}", records_to_insert.len());

                inserted_count += records_to_insert.len() as u32;
                break;
            }
    }
    });
    Ok(())
}
#[cfg(test)]
mod tests {
}