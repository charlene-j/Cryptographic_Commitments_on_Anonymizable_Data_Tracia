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

pub fn init_csv_file(name_data: &String, path_file: &String) -> Result<(), Box<dyn Error>>{

    let mut wtr = csv::Writer::from_path(path_file)?;
    wtr.write_record(&[name_data])?;
    wtr.flush()?; 
    
    Ok(())
}

pub fn write_csv_file(path_file: &String, data: &String) -> Result<(), Box<dyn Error>>{

    let file = OpenOptions::new().write(true).append(true).open(path_file)?;
    let mut wtr = Writer::from_writer(file);
    wtr.write_record(&[data])?;
    wtr.flush()?;
    
    Ok(())
}

pub fn import_data_f32(path_file: &String, column_index: usize, row_index: usize, precision: u32) -> Result<u32, Box<dyn Error>>{ // the precision corresponds to the number after the decimal point.

    let factor = 10u32.pow(precision);
    let mut rdr = Reader::from_path(&path_file)?;
    let record = rdr.records().nth(row_index-1).unwrap()?;
    let floatdata: f32 = record[column_index].parse()?;
    let integerdata: u32 = (floatdata * factor as f32).round() as u32; // convert the float in integer with a factor 10^precision.
    
    Ok(integerdata)
}

pub fn import_data_u32(path_file: &String, column_index: usize, row_index: usize) -> Result<u32, Box<dyn Error>>{
    let mut rdr = Reader::from_path(&path_file)?;
    let record = rdr.records().nth(row_index-1).unwrap()?;
    let data: u32 = record[column_index].parse()?; 
    
    Ok(data)
}
