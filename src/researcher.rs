use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use std::fs;
use std::path::{Path, PathBuf};
use crate::usefulfunction::*;
use crate::usefulstruct::*;
use crate::storedata::*;
use crate::commitscheme::*;
use crate::managecsv::*;
use crate::compute_eps;
use std::time::Instant;

// Verification of the correct usage of privacy budget.
pub fn researcher_privacy_budget_verification(name_data: &String, row_index: usize, path_eps: &PathBuf, path_set: &PathBuf){

    // Collect the data transmitted by the doctor and stored by the hospital
    let set = extract_setup(&path_set); // Collect the stored setup
    let extracted_eps = extract_float(&path_eps);
   
    let l1 = set.l1;
    let l2 = set.l2;
		
    let eps = compute_eps(l2.try_into().unwrap(),l1.try_into().unwrap());

    print!("Patient: {}; data: {}\n", name_data, row_index);
    assert!(extracted_eps == eps.into(), "The privacy budget is not correct\n");
    print!("The privacy budget is correct.\n");
}

// Generation and storage of the public seed.
pub fn researcher_gen_seed(name_data: &String, number_row: usize, folder_set: &String, folder_seed: &String){

    let folder_set_string = format!("{}/{}", folder_set, name_data);
    let folder_set = Path::new(&folder_set_string);
    let folder_seed_string = format!("{}/{}", folder_seed, name_data);
    let folder_seed = Path::new(&folder_seed_string);
    let _ = fs::create_dir_all(folder_seed); // Create the folder of the opening_key.
	
    for row_index in 1..=number_row{		
	let path_set = folder_set.join(format!("set_{}.txt", row_index));
		 
	// Collect the data transmitted by the hospital and stored by the researcher
    	let set = extract_setup(&path_set); // Collect the stored setup
    	
   	let l1 = set.l1;
	let l2 = set.l2;
		
	// Generate the random seed
	let theta = vec![rand_bitstring(l1), rand_bitstring(l2)];
		
	// Store the seed 
	let path_seed = folder_seed.join(format!("seed_{}.txt", row_index));
	let _= store_seed(theta, &path_seed); 
    }
    print!("The seeds are generated.\n");
}

// Verification of the signature of the commitment given the public key.
pub fn researcher_signature_verification(path_set: &PathBuf, path_commitment: &PathBuf, path_signature: &PathBuf, path_doctor_public_key: &PathBuf){		
    
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
    print!("The signature is correct.\n");
}

// Verification of the proof of correct commitment. 
pub fn researcher_proof_commitment_verification(name_data: &String, row_index: usize, path_set: &PathBuf, path_commitment: &PathBuf, path_proof_commitment: &PathBuf){

    // Collect the data transmitted by the doctor and stored by the hospital
    let set = extract_setup(&path_set); // Collect the stored setup
   
    let l1 = set.l1;
    let l2 = set.l2;
	
    let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
    let proof_commitment = extract_proofcommit(l1, l2, path_proof_commitment); // Collect the stored proof of commitment
    
    // Verify the proof
    let verify = ver_commit(set, commitment, proof_commitment);
    assert!(verify == true, "The data is not well committed.\n");
    print!("Patient: {}; data: {}\n", row_index, name_data);
    print!("The proof of commitment is correct.\n");
}

pub fn researcher_verify_opening_on_anonymized_data(column_index: usize, row_index: usize, b: bool, p: u32, path_set: &PathBuf, path_commitment: &PathBuf, path_seed: &PathBuf, path_proof_opening_ldp: &PathBuf, path_ano_data: &String){

    // Collect the data needed
    let set = extract_setup(&path_set); // Collect the stored setup
   
    let l1 = set.l1;
    let l2 = set.l2;
	
    let commitment = extract_commit(l1, l2, &path_commitment); // Collect the stored commitment
    let proof_openldp = extract_proofopenldp(path_proof_opening_ldp); // Collect the stored proof of opening
    let seed = extract_seed(l1, l2, path_seed);
	
    // Import the data
    let ano_data: u32;
    if b == false{
	ano_data = import_data_u32(&path_ano_data, column_index, row_index).expect("Impossible to import the data.");
    }
    else{ 
	ano_data = import_data_f32(&path_ano_data, column_index, row_index, p).expect("Impossible to import the data.");
    }
	
    // Convert the data in binary 
    let bin_ano_data = convert_u32_in_binary(ano_data, l2.try_into().unwrap());
    
    // Verify the proof
    let verify = ver_openldp(set, commitment, bin_ano_data, proof_openldp, seed); 
    assert!(verify == true, "The proof of opening with LDP is false.\n");
		
    print!("The proof of opening with LDP is true.\n");
}

// Phase executed by the Researcher to verify the signature, the proof of commitment and the proof of correct anonymization given the anonymized data.
pub fn researcher_verification(metadata: &Metadata, folder_eps: &String, folder_set: &String, folder_commitment: &String, folder_proof_commitment: &String, folder_seed: &String, folder_proof_openldp: &String, folder_signature: &String, path_doctor_public_key: &PathBuf, path_ano_data: &String){

    let start_res_verification_phase = Instant::now();
	
    // Parse metadata
    let name_data = &metadata.name;
    let number_row = metadata.nb_row;
    let b = metadata.fl;
    let p = metadata.pr;

    let folder_eps_string = format!("{}/{}", folder_eps, name_data);
    let folder_eps = Path::new(&folder_eps_string);	
    let folder_set_string = format!("{}/{}", folder_set, name_data);
    let folder_set = Path::new(&folder_set_string);
    let folder_commitment_string = format!("{}/{}", folder_commitment, name_data);
    let folder_commitment = Path::new(&folder_commitment_string);
    let folder_proof_commitment_string = format!("{}/{}", folder_proof_commitment, name_data);
    let folder_proof_commitment = Path::new(&folder_proof_commitment_string);
    let folder_seed_string = format!("{}/{}", folder_seed, name_data);
    let folder_seed = Path::new(&folder_seed_string);
    let folder_proof_openldp_string = format!("{}/{}", folder_proof_openldp, name_data);
    let folder_proof_openldp = Path::new(&folder_proof_openldp_string);
    let folder_signature_string = format!("{}/{}", folder_signature, name_data);
    let folder_signature = Path::new(&folder_signature_string); 
	
    for row_index in 1..=number_row{
    	let path_eps = folder_eps.join(format!("eps_{}.txt", row_index)); 
	let path_set = folder_set.join(format!("set_{}.txt", row_index));  
	let path_commitment = folder_commitment.join(format!("commitment_{}.txt", row_index));
	let path_proof_commitment = folder_proof_commitment.join(format!("proof_commitment_{}.txt", row_index));
	let path_seed = folder_seed.join(format!("seed_{}.txt", row_index)); 
	let path_proof_openldp = folder_proof_openldp.join(format!("proof_opening_ldp_{}.txt", row_index));
	let path_signature = folder_signature.join(format!("signature_{}.txt", row_index));
	
	// Verify the privacy budget is correct
    	researcher_privacy_budget_verification(&name_data, row_index, &path_eps, &path_set);
	
	// Verify the signature
	researcher_signature_verification(&path_set, &path_commitment, &path_signature, &path_doctor_public_key);
		
	// Verify the proof of commitment
	researcher_proof_commitment_verification(&name_data, row_index, &path_set, &path_commitment, &path_proof_commitment);
		
	// Verify the proof of opening with LDP
	researcher_verify_opening_on_anonymized_data(0, row_index, b, p, &path_set, &path_commitment, &path_seed, &path_proof_openldp, &path_ano_data);
    }
    let duration_res_verification_phase = start_res_verification_phase.elapsed();
    print!("Researcher Verification Phase took {:?} for {} data \n", duration_res_verification_phase, number_row);	
}
