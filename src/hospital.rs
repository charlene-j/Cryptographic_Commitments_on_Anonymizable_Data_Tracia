use rand_core::OsRng;    
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use std::fs;
use std::path::{Path, PathBuf};
use crate::usefulfunction::*;
use crate::usefulstruct::*;
use crate::storedata::*;
use crate::commitscheme::*;
use crate::managecsv::*;

pub fn hospital_proof_commitment_verification(name_data: &String, row_index: usize, path_set: &PathBuf, path_commitment: &PathBuf, path_proof_commitment: &PathBuf){

	// Collect the data transmitted by the doctor and stored by the hospital
    let set = extract_setup(&path_set); // Collect the stored setup
   
	let l1 = set.l1;
	let l2 = set.l2;
	
    let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
    let proof_commitment = extract_proofcommit(l1, l2, path_proof_commitment); // Collect the stored proof of commitment
    
    // Verify the proof
    let verify = ver_commit(set, commitment, proof_commitment);
    assert!(verify == true, "The proof of commitment is false.\n");
	print!("Patient: {}; data: {}\n", name_data, row_index);
	print!("The proof of commitment is true.\n");
}

pub fn hospital_signature_verification(path_set: &PathBuf, path_commitment: &PathBuf, path_signature: &PathBuf, path_doctor_public_key: &PathBuf){		
    
    // Collect the data transmitted by the Doctor and stored by the hospital
    let set = extract_setup(&path_set); // Collect the stored setup
   
	let l1 = set.l1;
	let l2 = set.l2;
    
    let doctor_public_key = extract_ristretto(&path_doctor_public_key); // Collect the stored public key
	let signature = extract_sig(&path_signature); // Collect the stored signature
	let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
	
    // Verify the signature with the public key of the doctor:   	    	
	let verify = ver(commitment.clone(),RISTRETTO_BASEPOINT_POINT,doctor_public_key,signature);
	assert!(verify == true, "The signature is false.\n");
	print!("The signature is true.\n");
}

pub fn hospital_opening_on_original_data(path_set: &PathBuf, path_opening_key: &PathBuf, path_commitment: &PathBuf, path_proof_opening: &PathBuf){
	
	let mut csrng = OsRng; // Random Number Generator based on the OS System (Crypto-Secure RNG)
	
	// Collect the data transmitted by the Doctor and stored by the hospital
    let set = extract_setup(&path_set); // Collect the stored setup
   
	let l1 = set.l1;
	let l2 = set.l2;
	
	let opening_key = extract_scalar(&path_opening_key); // Collect the stored opening key
	let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
	
	// Open the commitment
	let open = open(&mut csrng, set.clone(), opening_key, commitment.clone());
	
	// Store the proof of opening
	let proof_open = open.1;
	let _ = store_proofopen(&proof_open, &path_proof_opening);
	
	// verify the extraction of the proof
	
	print!("The commitment was opened on original data.\n");
}

pub fn hospital_verify_opening_on_original_data(column_index: usize, row_index: usize, b: bool, p: u32, path_data: &String, path_set: &PathBuf, path_commitment: &PathBuf, path_proof_opening: &PathBuf){

	// Collect the data needed
    let set = extract_setup(&path_set); // Collect the stored setup
   
	let l1 = set.l1;
	let l2 = set.l2;
	
	let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
	let proof_open = extract_proofopen(path_proof_opening); // Collect the stored proof of opening
	
	// Import the data
	let data: u32;
	if b == false{
		data = import_data_u32(&path_data, column_index, row_index).expect("Impossible to import the data.");
	}
	else{ 
		data = import_data_f32(&path_data, column_index, row_index, p).expect("Impossible to import the data.");
	}
	
	// Convert the data in binary 
    let bin_data = convert_u32_in_binary(data, l2.try_into().unwrap());
    
    // Verify the proof
    let verify = ver_open(set, commitment, bin_data, proof_open);
    assert!(verify == true, "The proof of opening is false.\n");
		
	print!("The proof of opening is true.\n");
}

pub fn hospital_opening_on_anonymized_data(name_data: &String, row_index: usize, b: bool, p:u32, path_set: &PathBuf, path_opening_key: &PathBuf, path_commitment: &PathBuf, path_public_seed: &PathBuf, path_proof_opening_ldp: &PathBuf, path_ano_data: &String){
	
	let mut csrng = OsRng; // Random Number Generator based on the OS System (Crypto-Secure RNG)
	
	// Collect the data transmitted by the Doctor and stored by the hospital
    let set = extract_setup(&path_set); // Collect the stored setup
   
	let l1 = set.l1;
	let l2 = set.l2;
	
	let opening_key = extract_scalar(&path_opening_key); // Collect the stored opening key
	let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
	let public_seed = extract_seed(l1, l2, &path_public_seed); // Collect the stored public seed
		
	// Open the commitment
	let openldp = openldp(&mut csrng, set, opening_key, commitment, public_seed);
	let ano_data = openldp.0;
	
	// Store the anonymized data
	let ano_data_u32: u32;
	let ano_data_f32: f32;
	if b == false{
		ano_data_u32 = convert_binary_in_u32(ano_data, l2.try_into().unwrap());
		let _= write_csv_file(&path_ano_data, &ano_data_u32.to_string());
	}
	else{
		ano_data_f32 = (convert_binary_in_u32(ano_data, l2.try_into().unwrap()) as f32)/ 10f32.powi(p as i32);
		let _= write_csv_file(&path_ano_data, &ano_data_f32.to_string());
	}
	
	// Store the proof of opening with LDP	
	let proof_openldp1 = openldp.1;
	let _ = store_proofopenldp(&proof_openldp1, &path_proof_opening_ldp);
	
	// Verify that the proof of opening can be correctly extracted	
	print!("Patient: {}; data: {}\n", row_index, name_data);
	print!("The commitment is opened on anonymized data.\n");
}

pub fn hospital_phase(metadata: &Metadata, path_data: &String, folder_set: &String, folder_opening_key: &String, folder_commitment: &String, folder_proof_commitment: &String, folder_proof_open: &String, folder_signature: &String, path_doctor_public_key: &PathBuf){

	// Parse metadata
	let name_data = &metadata.name;
	let column_index = metadata.col_index;
	let number_row = metadata.nb_row;
	let b = metadata.fl;
	let p = metadata.pr;

	let folder_set_string = format!("{}/{}", folder_set, name_data);
	let folder_set = Path::new(&folder_set_string);
	let folder_opening_key_string = format!("{}/{}", folder_opening_key, name_data);
	let folder_opening_key = Path::new(&folder_opening_key_string);
	let folder_commitment_string = format!("{}/{}", folder_commitment, name_data);
	let folder_commitment = Path::new(&folder_commitment_string);
	let folder_proof_commitment_string = format!("{}/{}", folder_proof_commitment, name_data);
	let folder_proof_commitment = Path::new(&folder_proof_commitment_string);
	let folder_proof_open_string = format!("{}/{}", folder_proof_open, name_data);
	let folder_proof_open = Path::new(&folder_proof_open_string);
	let folder_signature_string = format!("{}/{}", folder_signature, name_data);
	let folder_signature = Path::new(&folder_signature_string);
	let _ = fs::create_dir_all(folder_proof_open); 
	
	for row_index in 1..=number_row{
	
		let path_set = folder_set.join(format!("set_{}.txt", row_index)); 
		let path_opening_key = folder_opening_key.join(format!("opening_key_{}.txt", row_index)); 
		let path_commitment = folder_commitment.join(format!("commitment_{}.txt", row_index));
		let path_proof_commitment = folder_proof_commitment.join(format!("proof_commitment_{}.txt", row_index));
		let path_proof_open = folder_proof_open.join(format!("proof_opening_{}.txt", row_index));
		let path_signature = folder_signature.join(format!("signature_{}.txt", row_index));
    	
		// Verify the proof of commitment
		hospital_proof_commitment_verification(&name_data, row_index, &path_set, &path_commitment, &path_proof_commitment);
		
		// Verify the signature
		hospital_signature_verification(&path_set, &path_commitment, &path_signature, &path_doctor_public_key);
		
		// Open the commitment on the original data
		hospital_opening_on_original_data(&path_set, &path_opening_key, &path_commitment, &path_proof_open);
		
		// Verify the proof of opening
		hospital_verify_opening_on_original_data(column_index, row_index, b, p, &path_data, &path_set, &path_commitment, &path_proof_open);		
	} 
}

pub fn hospital_anonymization(metadata: &Metadata, folder_set: &String, folder_opening_key: &String, folder_commitment: &String, folder_seed: &String, folder_proof_openldp: &String, path_ano_data: &String){
	
	// Parse metadata
	let name_data = &metadata.name;
	let number_row = metadata.nb_row;
	let b = metadata.fl;
	let p = metadata.pr;
	
	let folder_set_string = format!("{}/{}", folder_set, name_data);
	let folder_set = Path::new(&folder_set_string);
	let folder_opening_key_string = format!("{}/{}", folder_opening_key, name_data);
	let folder_opening_key = Path::new(&folder_opening_key_string);
	let folder_commitment_string = format!("{}/{}", folder_commitment, name_data);
	let folder_commitment = Path::new(&folder_commitment_string);
	let folder_seed_string = format!("{}/{}", folder_seed, name_data);
	let folder_seed = Path::new(&folder_seed_string);
	let folder_proof_openldp_string = format!("{}/{}", folder_proof_openldp, name_data);
	let folder_proof_openldp = Path::new(&folder_proof_openldp_string);
	let _ = fs::create_dir_all(folder_proof_openldp); // Create the folder of the proof of opening with LDP.
	
    let _= init_csv_file(name_data, path_ano_data);
	
	for row_index in 1..=number_row{
		let path_set = folder_set.join(format!("set_{}.txt", row_index)); 
		let path_opening_key = folder_opening_key.join(format!("opening_key_{}.txt", row_index)); 
		let path_commitment = folder_commitment.join(format!("commitment_{}.txt", row_index));
		let path_proof_openldp = folder_proof_openldp.join(format!("proof_opening_ldp_{}.txt", row_index));
		
		// Collect the public seed sending by the researcher
		let path_public_seed = folder_seed.join(format!("seed_{}.txt", row_index));
		
		// Open the commitment on the anonymized data
		hospital_opening_on_anonymized_data(name_data, row_index, b, p, &path_set, &path_opening_key, &path_commitment, &path_public_seed, &path_proof_openldp, &path_ano_data);
		
	}
}
    

