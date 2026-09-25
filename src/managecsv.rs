#![allow(unused_imports)]
#![allow(unused_variables)]
use std::io;
use std::io::{IoSlice, Write, Read};
use std::error::Error;
use std::fs::OpenOptions;
use csv::{Reader, Writer, StringRecord};
use crate::usefulfunction::*;
use crate::usefulstruct::*;
use crate::privacybudget::*;
use crate::commitscheme::*;
use crate::storedata::*;
use crate::doctor::*;

pub fn init_csv_file(column_number: usize, row_number: usize, dataset_metadata: &Vec<Metadata>, path_file: &String) -> Result<(), Box<dyn Error>> {
    
    let mut wtr = csv::Writer::from_path(path_file)?;

    let mut headers: Vec<String> = Vec::new();

    for column_index in 0..column_number{
        headers.push(dataset_metadata[column_index].type_data.clone());
    }

    // Écriture des headers
    wtr.write_record(headers)?;

    // Création de n lignes remplies de 0
    let row = vec!["0"; column_number];

    for _ in 0..row_number{
        wtr.write_record(&row)?;
    }

    wtr.flush()?;

    Ok(())
}

pub fn write_csv_file(path_file: &String, column_index: usize, row_index: usize, data: &String) -> Result<(), Box<dyn Error>> {

    let mut reader = csv::Reader::from_path(path_file)?;

    let headers = reader.headers()?.clone();

    let mut records: Vec<Vec<String>> = Vec::new();

    for result in reader.records() {
        let record = result?;
        records.push(record.iter().map(|x| x.to_string()).collect());
    }

    // Modify the corresponding cell
    records[row_index-1][column_index] = data.clone();

    // Re write the file
    let mut writer = csv::Writer::from_path(path_file)?;

    writer.write_record(&headers)?;

    for record in records {
        writer.write_record(&record)?;
    }

    writer.flush()?;

    Ok(())
}

pub fn get_cell(path_file: &String, column_index: usize, row_index: usize
) -> Result<f64, Box<dyn Error>> {
    let mut reader = csv::Reader::from_path(path_file)?;

    for (i, result) in reader.records().enumerate() {
        let record = result?;

        if i == row_index {
            let value: f64 = record[column_index].parse()?;
            return Ok(value);
        }
    }

    Err("Row not found".into())
}

pub fn import_data_f64(path_file: &String, column_index: usize, row_index: usize, precision: u32) -> Result<u32, Box<dyn Error>>{ // the precision corresponds to the number after the decimal point.

    let factor = 10u32.pow(precision);
    let mut rdr = Reader::from_path(&path_file)?;
    let record = rdr.records().nth(row_index-1).unwrap()?;
    let floatdata: f64 = record[column_index].parse()?;
    let integerdata: u32 = (floatdata * factor as f64).round() as u32; // convert the float in integer with a factor 10^precision.
    
    Ok(integerdata)
}

pub fn import_data_u32(path_file: &String, column_index: usize, row_index: usize) -> Result<u32, Box<dyn Error>>{
    let mut rdr = Reader::from_path(&path_file)?;
    let record = rdr.records().nth(row_index-1).unwrap()?;
    let data: u32 = record[column_index].parse()?; 
    
    Ok(data)
}
