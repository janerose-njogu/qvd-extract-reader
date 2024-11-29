use bitvec::prelude::*;
use bitvec::slice::BitSlice;
use pyo3::PyErr;
use duckdb::{params, Connection, Result}; 
use pyo3::wrap_pyfunction;
use pyo3::prelude::*;
use quick_xml::de::from_str;
use qvd_structure::{QvdFieldHeader, QvdTableHeader};
use std::io::SeekFrom;
use std::io::{self, Read};
use std::path::Path;
use std::slice::ChunksMut;
use std::str;
use std::{collections::HashMap, fs::File};
use std::{convert::TryInto, io::prelude::*};
use regex::Regex;

pub mod qvd_structure;

const DEFAULT_CHUNK_SIZE: usize = 2; // Default chunk size for reading data in GB.

#[pymodule]
fn qvd_utils(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(read_qvd_file, m)?)?;

    Ok(())
}

#[pyfunction]
fn read_qvd_file(py: Python, qvd_file_name: String, chunk_size: Option<usize>) -> PyResult<()> {
    let chunk_size_in_bytes: usize = if chunk_size.unwrap_or(0) > 0 {
        chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE) * 1024 * 1024 * 1024
    } else {
        DEFAULT_CHUNK_SIZE * 1024 * 1024 * 1024
    };
    let duck_db_conn: Connection = Connection::open_in_memory().expect("Error opening connection to DuckDB");

    let xml: String = get_xml_data(&qvd_file_name).expect("Error reading QVD extract file");
    // let dict = PyDict::new(py);
    let binary_section_offset: usize = xml.as_bytes().len();

    let qvd_structure: QvdTableHeader = from_str(&xml).unwrap();
    let mut symbol_map: HashMap<String, Vec<Option<String>>> = HashMap::new();

    // Define table schema in DuckDB based on QVD fields
    let formatted_table_name: String = format_convert_to_snake_case(&qvd_file_name);
    let mut create_table_query: String = format!("CREATE TABLE {} (", formatted_table_name);
    for field in &qvd_structure.fields.headers {
        create_table_query.push_str(&format!("{} TEXT,", field.field_name));
    }
    create_table_query.pop(); // Remove trailing comma
    create_table_query.push_str(");");

    // Execute the CREATE TABLE query in DuckDB
    duck_db_conn.execute(&create_table_query, []).expect("Error creating table");

    // Open the QVD file and process it
    if let Ok(f) = File::open(&qvd_file_name) {
        let mut binary_section_offset = binary_section_offset;
        
        loop {
            // Recursively read the next chunk of the file
            let buf: Vec<u8> = read_qvd_extract_data_to_buf(f.try_clone().unwrap(), binary_section_offset, chunk_size_in_bytes);
            
            // If no more data is read, exit the loop
            if buf.is_empty() {
                break;
            }
            let rows_start = 0;
            let rows_end = buf.len();
            let rows_section = &buf[rows_start..rows_end];
            let record_byte_size = qvd_structure.record_byte_size;

            for field in &qvd_structure.fields.headers {
                symbol_map.insert(
                    field.field_name.clone(),
                    get_symbols_as_strings(&buf, &field),
                );
                let symbol_indexes = get_row_indexes(&rows_section, &field, record_byte_size);
                let column_values = match_symbols_with_indexes(&symbol_map[&field.field_name], &symbol_indexes);
                dbg!(&symbol_indexes);
                dbg!(&column_values);
            }
            //     // Insert statement
            //     let insert_query = format!(
            //         "INSERT INTO {} ({}) VALUES ({})",
            //         formatted_table_name,
            //         qvd_structure
            //             .fields
            //             .headers
            //             .iter()
            //             .map(|f| f.field_name.clone())
            //             .collect::<Vec<String>>()
            //             .join(", "),
            //         qvd_structure
            //             .fields
            //             .headers
            //             .iter()
            //             .map(|_| "?".to_string())
            //             .collect::<Vec<String>>()
            //             .join(", ")
            //     );
            //     let mut row_values = Vec::new();
            //     for value in column_values {
            //         row_values.push(value.unwrap_or_default());
            //     }
            //     // Convert row_values to Value
            //     let duckdb_values: Vec<Value> = row_values
            //         .iter()
            //         .map(|value| Value::Text(value.clone()))
            //         .collect();

            //     let insert_statement = duck_db_conn.prepare(&insert_query).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("DuckDB error: {}", e)))?;
            //     // Execute the INSERT query
            //     insert_statement.execute(&duckdb_values[..]).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("DuckDB error: {}", e)))?;
            // }
            // Update the binary section offset for the next chunk
            binary_section_offset += buf.len();
        }
    }
    Ok(())
}

fn read_qvd_extract_data_to_buf(mut f: File, offset: usize, chunk_size: usize) -> Vec<u8> {
    let mut buf = vec![0; chunk_size];
    f.seek(SeekFrom::Start(offset as u64)).unwrap();
    let bytes_read = f.read(&mut buf).unwrap();
    buf.truncate(bytes_read); // Resize the buffer to the actual number of bytes read
    buf
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
    let start = field.offset;
    let end = start + field.length;
    let mut string_start: usize = 0;
    let mut strings: Vec<Option<String>> = Vec::new();

    let mut i = start;
    while i < end {
        let byte = &buf[i];
        // Check first byte of symbol. This is not part of the symbol but tells us what type of data to read.
        match byte {
            0 => {
                // Strings are null terminated
                // Read bytes from start fo string (string_start) up to current byte.
                let utf8_bytes = buf[string_start..i].to_vec().to_owned();
                let value = String::from_utf8(utf8_bytes).unwrap_or_else(|_| {
                    panic!(
                    "Error parsing string value in field: {}, field offset: {}, byte offset: {}",
                    field.field_name, start, i
                )
                });
                strings.push(Some(value));
                i += 1;
            }
            1 => {
                // 4 byte integer
                let target_bytes = buf[i + 1..i + 5].to_vec();
                let byte_array: [u8; 4] = target_bytes.try_into().unwrap();
                let numeric_value = i32::from_le_bytes(byte_array);
                strings.push(Some(numeric_value.to_string()));
                i += 5;
            }
            2 => {
                // 4 byte double
                let target_bytes = buf[i + 1..i + 9].to_vec();
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
        let val = match bit {
            true => 1,
            false => 0,
        };
        v.push(val);
    }
    v
}

fn get_xml_data(qvd_file_name: &str) -> Result<String, io::Error> {
    match read_file(qvd_file_name) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double() {
        let buf: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x7a, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x50, 0x7a, 0x40,
        ];
        let field = QvdFieldHeader {
            length: buf.len(),
            offset: 0,
            field_name: String::new(),
            bias: 0,
            bit_offset: 0,
            bit_width: 0,
        };
        let res = get_symbols_as_strings(&buf, &field);
        let expected: Vec<Option<String>> = vec![Some(420.0.to_string()), Some(421.0.to_string())];
        assert_eq!(expected, res);
    }

    #[test]
    fn test_int() {
        let buf: Vec<u8> = vec![0x01, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x14, 0x00, 0x00, 0x00];
        let field = QvdFieldHeader {
            length: buf.len(),
            offset: 0,
            field_name: String::new(),
            bias: 0,
            bit_offset: 0,
            bit_width: 0,
        };
        let res = get_symbols_as_strings(&buf, &field);
        let expected = vec![Some(10.0.to_string()), Some(20.0.to_string())];
        assert_eq!(expected, res);
    }

    #[test]
    #[rustfmt::skip]
    fn test_mixed_numbers() {
        let buf: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x7a, 0x40, 
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x7a, 0x40,
            0x01, 0x01, 0x00, 0x00, 0x00, 
            0x01, 0x02, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x00, 0x37, 0x30, 0x30, 0x30, 0x00,
            0x06, 0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00, 0x38, 0x36, 0x35, 0x2e, 0x32, 0x00
        ];
        let field = QvdFieldHeader {
            length: buf.len(),
            offset: 0,
            field_name: String::new(),
            bias: 0,
            bit_offset: 0,
            bit_width: 0,
        };
        let res = get_symbols_as_strings(&buf, &field);
        let expected: Vec<Option<String>> = vec![
            Some(420.to_string()),
            Some(421.to_string()),
            Some(1.to_string()),
            Some(2.to_string()),
            Some(7000.to_string()),
            Some(865.2.to_string())
        ];
        assert_eq!(expected, res);
    }

    #[test]
    fn test_string() {
        let buf: Vec<u8> = vec![
            4, 101, 120, 97, 109, 112, 108, 101, 32, 116, 101, 120, 116, 0, 4, 114, 117, 115, 116,
            0,
        ];
        let field = QvdFieldHeader {
            length: buf.len(),
            offset: 0,
            field_name: String::new(),
            bias: 0,
            bit_offset: 0,
            bit_width: 0,
        };
        let res = get_symbols_as_strings(&buf, &field);
        let expected = vec![Some("example text".into()), Some("rust".into())];
        assert_eq!(expected, res);
    }

    #[test]
    #[rustfmt::skip]
    fn test_utf8_string() {
        let buf: Vec<u8> = vec![
            0x04, 0xE4, 0xB9, 0x9F, 0xE6, 0x9C, 0x89, 0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87, 0xE7,
            0xAE, 0x80, 0xE4, 0xBD, 0x93, 0xE5, 0xAD, 0x97, 0x00,
            0x04, 0xF0, 0x9F, 0x90, 0x8D, 0xF0, 0x9F, 0xA6, 0x80, 0x00,
        ];

        let field = QvdFieldHeader {
            length: buf.len(),
            offset: 0,
            field_name: String::new(),
            bias: 0,
            bit_offset: 0,
            bit_width: 0,
        };
        let res = get_symbols_as_strings(&buf, &field);
        let expected = vec![Some("也有中文简体字".into()), Some("🐍🦀".into())];
        assert_eq!(expected, res);
    }

    #[test]
    fn test_mixed_string() {
        let buf: Vec<u8> = vec![
            4, 101, 120, 97, 109, 112, 108, 101, 32, 116, 101, 120, 116, 0, 4, 114, 117, 115, 116,
            0, 5, 42, 65, 80, 1, 49, 50, 51, 52, 0, 6, 1, 1, 1, 1, 1, 1, 1, 1, 100, 111, 117, 98,
            108, 101, 0,
        ];
        let field = QvdFieldHeader {
            length: buf.len(),
            offset: 0,
            field_name: String::new(),
            bias: 0,
            bit_offset: 0,
            bit_width: 0,
        };
        let res = get_symbols_as_strings(&buf, &field);
        let expected = vec![
            Some("example text".into()),
            Some("rust".into()),
            Some("1234".into()),
            Some("double".into()),
        ];
        assert_eq!(expected, res);
    }

    #[test]
    fn test_bitslice_to_vec() {
        let mut x: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x11, 0x01, 0x22, 0x02, 0x33, 0x13, 0x34, 0x14, 0x35,
        ];
        let bits = BitSlice::<Msb0, _>::from_slice(&mut x[..]).unwrap();
        let target = &bits[27..32];
        let binary_vec = bitslice_to_vec(&target);

        let mut sum: u32 = 0;
        for bit in binary_vec {
            sum <<= 1;
            sum += bit as u32;
        }
        assert_eq!(17, sum);
    }

    #[test]
    fn test_get_row_indexes() {
        let buf: Vec<u8> = vec![
            0x00, 0x14, 0x00, 0x11, 0x01, 0x22, 0x02, 0x33, 0x13, 0x34, 0x24, 0x35,
        ];
        let field = QvdFieldHeader {
            field_name: String::from("name"),
            offset: 0,
            length: 0,
            bit_offset: 10,
            bit_width: 3,
            bias: 0,
        };
        let record_byte_size = buf.len();
        let res = get_row_indexes(&buf, &field, record_byte_size);
        let expected: Vec<i64> = vec![5];
        assert_eq!(expected, res);
    }
}