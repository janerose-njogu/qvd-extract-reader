use bitvec::prelude::*;
use pyo3::prelude::*;
use quick_xml::de::from_str;
use qvd_structure::{QvdTableHeader, QvdFieldHeader};
use std::io::{Error as ioError, BufReader, BufRead, SeekFrom, Seek, Read, Write};
use std::error::Error as standardError;
use std::path::Path;
use std::fs::{self, File};
use std::result::Result;
use std::str::from_utf8;
use std::collections::HashMap;

pub mod qvd_structure;

#[pymodule]
fn qvd_utils(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_xml_data, m)?)?;
    m.add_function(wrap_pyfunction!(extract_binary_data, m)?)?;
    Ok(())
}

#[pyfunction]
fn extract_xml_data(file_path: &str) -> Result<String, ioError> {
    match parse_xml_section(file_path) {
        Ok(mut reader) => {
            let mut buffer: Vec<u8> = Vec::new();
            // There is a line break, carriage return and a null terminator between the XMl and data
            // Find the null terminator
            reader.read_until(0, &mut buffer).expect("Failed to read file");
            let xml_string = from_utf8(&buffer[..]).expect("XML section contains invalid UTF-8 chars");
            Ok(xml_string.to_owned())
        }
        Err(e) => Err(e),
    }
}

fn parse_xml_section<P>(filename: P) -> Result<BufReader<File>, ioError>
where
    P: AsRef<Path>,
{
    let file: File = File::open(filename)?;
    Ok(BufReader::new(file))
}

#[pyfunction]
fn extract_binary_data(file_path: String, chunk_size: usize) -> PyResult<String> {
    let xml: String = extract_xml_data(&file_path).expect("Error reading file");
    let binary_section_offset: usize = xml.as_bytes().len();
    let qvd_structure: QvdTableHeader = from_str(&xml).unwrap();
    let mut symbol_map: HashMap<String, Vec<Option<String>>> = HashMap::new();
    let record_byte_size = qvd_structure.record_byte_size;

    let mut file = File::open(&file_path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to open file '{}': {}", file_path, e))
    })?;

    let output_folder_path = Path::new("output");
    if !output_folder_path.exists() {
        fs::create_dir_all(output_folder_path)?;
    }

    let subfolders = ["bytes".to_string(), "data".to_string(), "partitions".to_string()];

    for subfolder in subfolders.iter() {
        let subfolder_path = output_folder_path.join(subfolder);
        if !subfolder_path.exists() {
            fs::create_dir_all(subfolder_path)?;
        }
    }
        
    for field in qvd_structure.fields.headers {
        let total_offset = binary_section_offset + field.offset;
        file.seek(SeekFrom::Start(total_offset as u64))?;

        let mut file_buffer = BufReader::new(&file);

        let file_name = clean_field_name(&field.field_name);
        let mut byte_data_file = File::create(format!("{}/{}/{}.txt", output_folder_path.display(), "bytes".to_string(), file_name))?;
        let mut field_data_file = File::create(format!("{}/{}/{}.txt", output_folder_path.display(), "data".to_string(), file_name))?;
        let mut byte_partition_file = File::create(format!("{}/{}/{}.txt", output_folder_path.display(), "partitions".to_string(), file_name))?;

        let mut remaining_bytes = field.length;
        let mut total_bytes_read = 0;
        
        // track the first chunk of field values
        let mut is_first_chunk = true;
        // by default the first byte will evaluate to UTF-8 string
        let mut first_byte: u8 = 0;
        
        while remaining_bytes > 0 {
            // BYTES EXTRACTION
            // Adjust the chunk size based on the remaining bytes and valid byte boundaries
            // buffer size = chunk_size if chunk_size is smaller than the field data else extract and parse the entire field at once
            let current_chunk_size = remaining_bytes.min(chunk_size);
            
            let mut byte_buffer = vec![0u8; current_chunk_size];
            let bytes_read = file_buffer.read(&mut byte_buffer)?;
            if bytes_read == 0 {
                eprintln!("Error: Could not read data for field: {}", field.field_name);
                break;
            }
            if is_first_chunk {
                // Extract the first byte from the first chunk
                first_byte = byte_buffer[0];
                is_first_chunk = false;
            }
            // Evaluate valid byte boundary based on chunk_data
            let data_partitions = partition_byte_array(&byte_buffer, first_byte);
            let adjusted_chunk_size = match data_partitions {
                Ok(partitions) => {
                    writeln!(byte_partition_file, "{:?}", partitions)?;
                    let adjusted_size = adjust_chunk_size(current_chunk_size, &partitions);
                    adjusted_size
                },
                Err(e) => {
                    eprintln!("Error partitioning byte array: {}", e);
                    break;
                }
            };
    
            // Reallocate the buffer if adjusted chunk size differs
            if adjusted_chunk_size != current_chunk_size {
                byte_buffer.truncate(adjusted_chunk_size);
            }
            writeln!(byte_data_file, "{:?}", byte_buffer)?;
            // if field.field_name == "Work Unit Name"{
            println!("Field Name: {}", field.field_name);
            println!("Field Length: {:?}", field.length);
            
           
            // BYTES PARSING\PROCESSING
            if first_byte == 0 {
                parse_null_terminated_utf8(&byte_buffer, &mut field_data_file);
            }
            else if first_byte == 1 {
                parse_integer_byte(&byte_buffer, &mut field_data_file);
            }
            else if first_byte == 2 {
                parse_double_byte(&byte_buffer, &mut field_data_file);
            }
            else if first_byte == 4 {
                parse_utf8_from_bytes_4(&byte_buffer, &mut field_data_file);
            } 
            else if first_byte == 5 {
                parse_utf8_from_bytes_5(&byte_buffer, &mut field_data_file);
            } 
            else {
                process_unknown_byte(&byte_buffer, &mut field_data_file);
            }
            total_bytes_read += bytes_read;
            remaining_bytes -= bytes_read;

            file_buffer.consume(byte_buffer.len());
            
            if remaining_bytes == 0 {
                break;
            }
        // symbol_map.insert(field.field_name.clone(), parse_byte_data(&byte_buffer, &field));
        // let symbol_indexes = match get_row_indexes(&byte_buffer, &field, field.length){
        //     Ok(indexes) => indexes,
        //     Err(err) => {
        //         eprintln!("Error getting row indexes for field {}: {}", field.field_name, err);
        //         vec![]
        //     },
        // };
        // let column_values = match_symbols_with_indexes(&symbol_map[&field.field_name], &symbol_indexes); 
    }
}
    Ok("Hello".to_string())
}

fn clean_field_name(field_name: &str) -> String {
    // Allow alphanumeric characters and underscores
    field_name.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect()
        
}

fn remove_non_printable(input: &str) -> String {
    input.chars().filter(|c| {
        c.is_ascii_graphic() || c.is_whitespace()
    }).filter(|c| *c != '\n' && *c != '\t' && *c != '"').collect()
}

fn adjust_chunk_size(chunk_size: usize, byte_partitions: &[(usize, usize)]) -> usize {
    for &(start, end) in byte_partitions {
        if chunk_size == end {
            // valid byte chunk
            return chunk_size;
        } else if start < chunk_size && chunk_size < end {
            // modify chunk_size to avoid parsing incomplete and invalid byte chunks
            return start;
        }
    }
    // default case
    chunk_size
}

fn partition_byte_array(byte_string: &[u8], first_byte: u8) -> Result<Vec<(usize, usize)>, Box<dyn standardError>> {
    let mut partitions = Vec::new();
    let mut current_index = 0;

    while current_index < byte_string.len() {
        let next_index = get_next_data_position(&byte_string, first_byte, current_index)?;
        partitions.push((current_index, next_index)); 
        current_index = next_index;
    }
    Ok(partitions)
}


fn get_next_data_position(byte_string: &[u8], first_byte: u8, mut current_index: usize) -> Result<usize, Box<dyn standardError>> {
    if current_index >= byte_string.len() {
        return Err("Reached end of byte_string.".into());
    }
    // current_index += 1; // Skip the type byte
    match first_byte {
        0 => {
            // null terminated UTF8 string
            while current_index < byte_string.len() && byte_string[current_index] != 0 {
                current_index += 1;
            }
            current_index += 1;
            Ok(current_index)
        },
        1 => {
            // 4 byte integer - also with a null terminated string
            while current_index < byte_string.len() {
                if byte_string[current_index] == 0 {
                    break;
                }
                current_index += 1;
            }
            current_index += 1;
            Ok(current_index)
        },
        2 => {
            // 4 byte double
            current_index += 8;
            Ok(current_index)
        },
        4 => {
            // Beginning of a null terminated string type. 
            // Mark where string value starts, excluding preceding byte 0x04
            current_index += 1;
            Ok(current_index)
        },
        5 => {
            // 4 bytes of unknown followed by null terminated string. Skip the 4 bytes
            current_index += 5;
            Ok(current_index)
        },
        6 => {
            // 8 bytes of unknown followed by null terminated string. Skip the 8 bytes before string
            current_index += 9;
            Ok(current_index)
        },
        _ => {
            // Part of a string, do nothing until null terminated string
            current_index += 1;
            Ok(current_index)
        }
    }
}

fn process_utf8_string(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    // null terminated UTF8 string
    let segments  = byte_string.split(|&byte| byte == 0);
    for segment in segments {
        let segment = if segment.is_empty() {
            segment
        } else {
            &segment[1..] // Skip the first byte
        };

        match String::from_utf8(segment.to_vec()) {
            Ok(ascii_string) => {
                writeln!(data_file, "{}", ascii_string)?;
            }
            Err(e) => {
                writeln!(data_file, "Failed to convert {}", e)?;
            }
        }
    }
    Ok(())
}

fn parse_utf8_from_bytes_4(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    let mut current_byte_index = 0;

    while current_byte_index < byte_string.len() {
        if byte_string[current_byte_index] == 4 {
            current_byte_index += 1;
            let string_start = current_byte_index;

            if let Some(null_pos) = byte_string[current_byte_index..].iter().position(|&b| b == 0) {
                let string_end = current_byte_index + null_pos;
                if let Ok(string_value) = String::from_utf8(byte_string[string_start..string_end].to_vec()) {
                    writeln!(data_file, "{}", string_value)?;
                } else {
                    writeln!(data_file, "")?;
                }
                current_byte_index = string_end + 1;
            } else {
                break;
            }
        } else {
            current_byte_index += 1;
        }
    }
    Ok(())
}

fn parse_utf8_from_bytes_5(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    let mut current_byte_index = 0;

    while current_byte_index < byte_string.len() {
        if byte_string[current_byte_index] == 5 {
            current_byte_index += 5;
            let string_start = current_byte_index;
            if let Some(null_pos) = byte_string[current_byte_index..].iter().position(|&b| b == 0) {
                let string_end = current_byte_index + null_pos;
                if let Ok(string_value) = String::from_utf8(byte_string[string_start..string_end].to_vec()) {
                    writeln!(data_file, "{}", string_value)?;
                } else {
                    writeln!(data_file, "{}", "")?;
                }
                current_byte_index = string_end + 1;
            } else {
                break;
            }
        } else {
            current_byte_index += 1;
        }
    }
    Ok(())
}

fn parse_integer_byte(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    let mut current_byte_index = 0;
    while current_byte_index + 5 <= byte_string.len() {
        let target_bytes = byte_string[current_byte_index + 1..current_byte_index + 5].to_vec();
        let byte_array: [u8; 4] = target_bytes.try_into().unwrap();
        let numeric_value = i32::from_le_bytes(byte_array);
        writeln!(data_file, "{}", numeric_value)?;
        current_byte_index += 5;
    }
    Ok(())
}

fn parse_double_byte(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    let mut current_byte_index = 0;
    while current_byte_index + 9 <= byte_string.len() {
        let target_bytes = byte_string[current_byte_index + 1..current_byte_index + 9].to_vec();
        let byte_array: [u8; 8] = target_bytes.try_into().unwrap();
        let numeric_value = f64::from_le_bytes(byte_array);
        writeln!(data_file, "{}", numeric_value)?;
        current_byte_index += 9;
    }
    Ok(())
}

fn parse_null_terminated_utf8(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    let mut parsed_strings = Vec::new();
    let mut current_byte_index = 0;

    while current_byte_index < byte_string.len() {
        if let Some(string_end) = byte_string[current_byte_index..].iter().position(|&b| b == 0){
            let string_start = current_byte_index;
            let utf8_bytes = byte_string[string_start..current_byte_index + string_end].to_vec();
            let string_value = String::from_utf8(utf8_bytes).unwrap_or_else(|_| "".to_string());
            parsed_strings.push(Some(string_value));
            current_byte_index += string_end + 1;
        } else {
            break;
        }
    }
    for string in parsed_strings {
        if let Some(inner_value) = string {
            writeln!(data_file, "{:?}", remove_non_printable(&inner_value))?;
        }
    }
    Ok(())
}

fn process_unknown_byte(byte_string: &[u8], data_file: &mut File) -> Result<(), Box<dyn standardError>> {
    // unknown byte values
    for byte in byte_string {
        writeln!(data_file, "{}", byte)?;
    }
    Ok(())
}


fn parse_byte_data(byte_string: &[u8], first_byte: u8, field: &QvdFieldHeader) -> Vec<Option<String>> {
    let mut parsed_strings: Vec<Option<String>> = Vec::new();
    let mut current_byte_index = 0;
    let mut string_start: usize = 0;
    while current_byte_index < byte_string.len() {
        match first_byte {
            0 => {
                // null terminated UTF8 string
                let utf8_bytes = byte_string[string_start..current_byte_index].to_vec().to_owned();
                let string_value = String::from_utf8(utf8_bytes.clone()).unwrap_or_else(|_| "".to_string());
                parsed_strings.push(Some(string_value));
                current_byte_index += 1;
            }
            1 => { 
                // 4 byte integer
                let target_bytes = byte_string[current_byte_index + 1..current_byte_index + 5].to_vec();
                let byte_array: [u8; 4] = target_bytes.try_into().unwrap();
                let numeric_value = i32::from_le_bytes(byte_array);
                parsed_strings.push(Some(numeric_value.to_string()));
                current_byte_index += 5;
            }
            2 => {
                // 4 byte double
                let target_bytes = byte_string[current_byte_index + 1..current_byte_index + 9].to_vec();
                let byte_array: [u8; 8] = target_bytes.try_into().unwrap();
                let numeric_value = f64::from_le_bytes(byte_array);
                parsed_strings.push(Some(numeric_value.to_string()));
                current_byte_index += 9;
            }
            4 => {
                // Beginning of a null terminated string type
                // Mark where string value starts, excluding preceding byte 0x04
                current_byte_index += 1;
                string_start = current_byte_index;
            }
            5 => {
                // 4 bytes of unknown followed by null terminated string. 
                // Skip the 4 bytes
                current_byte_index += 5;
                string_start = current_byte_index;
            }
            6 => {
                // 8 bytes of unknown followed by null terminated string. Skip the 8 bytes before string
                current_byte_index += 9;
                string_start = current_byte_index;
            }
            _ => {
                // Part of a string, do nothing until null terminated string
                current_byte_index += 1;
            }
        }
    }
    parsed_strings
}

fn match_symbols_with_indexes(symbols: &[Option<String>], pointers: &[i64]) -> Vec<Option<String>> {
    let mut cols: Vec<Option<String>> = Vec::new();
    for pointer in pointers.iter() {
        if symbols.is_empty() || *pointer < 0 || *pointer as usize >= symbols.len() {
            cols.push(None);
            eprintln!("Warning: Pointer value out of bounds: {}", pointer);
        } else {
            cols.push(symbols[*pointer as usize].clone());
        }
    }
    cols
}

fn get_row_indexes(buf: &[u8], field: &QvdFieldHeader, record_byte_size: usize) -> Result<Vec<i64>, Box<dyn standardError>> {
    let mut indexes: Vec<i64> = Vec::new();
    let mut offset = 0; 

    while offset < buf.len() {
        let chunk = &buf[offset..offset + record_byte_size]; 
        // Reverse the bytes in the record
        let mut reversed_chunk = chunk.to_vec();
        reversed_chunk.reverse(); 

        let bits = BitSlice::<Msb0, _>::from_slice(&reversed_chunk).unwrap();
        let start = bits.len().saturating_sub(field.bit_offset as usize); 
        let end = start.saturating_sub(field.bit_width as usize); 

        if end < 0 { 
            return Err("Field extends beyond record boundary".into()); 
        }

        let binary = bitslice_to_vec(&bits[end..start]); 
        let index = binary_to_u32(binary); 
        indexes.push((index as i32 + field.bias) as i64);

        offset += record_byte_size;
    }
    Ok(indexes)
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