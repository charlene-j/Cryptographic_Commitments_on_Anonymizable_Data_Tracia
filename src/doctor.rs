use rand_core::OsRng;    
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use std::fs;
use std::path::{Path, PathBuf};
use crate::usefulfunction::*;
use crate::usefulstruct::*;
use crate::storedata::*;
use crate::commitscheme::*;
use crate::privacybudget::*;
use crate::managecsv::*;
use std::time::Instant;

// Generation and Storage of public and private key of the Doctor.
pub fn doctor_keys_generation(path_doctor_public_key: &PathBuf, path_doctor_private_key: &PathBuf){
	
    let mut csrng = OsRng; // Random Number Generator based on the OS System (Crypto-Secure RNG)
    
    // Key Generation
    let (doctor_private_key, doctor_public_key) = gen(&mut csrng, RISTRETTO_BASEPOINT_POINT); 
	
    // Store the public key
    let _ = store_ristretto(&doctor_public_key, &path_doctor_public_key);
    
    // Verify that we can extract the public key from the file
    let extracted_public_key = extract_ristretto(&path_doctor_public_key);
    assert!(extracted_public_key == doctor_public_key, "The public key in the file in not equal to the real public key."); 
    
    // Store the private key
    let _ = store_scalar(&doctor_private_key, &path_doctor_private_key);
    
    // Verify that we can extract the private key from the file
    let extracted_private_key = extract_scalar(&path_doctor_private_key);
    assert!(extracted_private_key == doctor_private_key, "The private key in the file in not equal to the real private key.");
    
    let meta_privk = fs::metadata(&path_doctor_private_key).expect("Error");
    let meta_pubk = fs::metadata(&path_doctor_public_key).expect("Error");
    let privk_size = meta_privk.len();
    let pubk_size = meta_pubk.len();
    print!("The private/public keys are correctly generated and stored ({}/{} bytes).\n", privk_size, pubk_size);
}

// Computation of the parameter l1 according to the privacy budget.
pub fn doctor_precomputation(name_data: &String, row_index: usize, max_eps: f32, l2: u32, path_eps: &PathBuf) -> u32{ // b = 0 for integer and b = 1 for flot; p is the precision in the case b = 1. The precision corresponds to the number after the comma. For instance, if we have age = 20.264, p = 3.
	
    // Compute the parameter l1 
    let l1 = compute_l1(l2, max_eps);

    // Compute the exact privacy budget
    let eps = compute_eps(l2, l1);
    let _= store_float(eps, &path_eps);
	
    print!("Patient: {}; data: {}, eps: {}.\n", row_index, name_data, eps);
	
    return l1
}

// Generation and Storage of the setup
pub fn doctor_setup_generation_and_storage(l1: u32, l2: u32, path_set: &PathBuf){

    let mut csrng = OsRng; // Random Number Generator based on the OS System (Crypto-Secure RNG)
    
    // Setup Operation
    let set = setup(&mut csrng, l1.try_into().unwrap(), l2.try_into().unwrap()); 
    
    // Store set
    let _ = store_setup(&set, &path_set);
    
    // Verify that we can extract set from the file
    let extracted_set = extract_setup(&path_set);
    assert!(extracted_set == set, "The setup in the file in not equal to the real setup."); 
    
    let meta = fs::metadata(&path_set).expect("Error");
    let set_size = meta.len();
    print!("The setup is generated and stored ({} bytes).\n", set_size);
}

// Generation and Storage of the opening key, the commitment and the proof of correct commitment.
pub fn doctor_commit_generation_and_storage(column_index: usize, row_index: usize, l1: u32, l2: u32, b: bool, p: u32, path_data: &String, path_set: &PathBuf, path_opening_key: &PathBuf, path_commitment: &PathBuf, path_proof_commitment: &PathBuf){

    let mut csrng = OsRng; // Random Number Generator based on the OS System (Crypto-Secure RNG)
    
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
    
    // Choose a random seed theta
    let theta = vec![rand_bitstring(l1.try_into().unwrap()), rand_bitstring(l2.try_into().unwrap())];
    
    // Extract the setup
    let set = extract_setup(&path_set);
    	
    // Commit phase:			
    // Commit operation
    let com = commit(&mut csrng, set.clone(), (&bin_data).to_vec(), theta.clone());
   		
    // Assign produced values
    let k = com.0; // opening key
    let c = com.1; // commitment
    let p_com = com.2; // proof of commitment (proof that values are well committed in binary)
    	
    // Store the opening key in a file
    let _ = store_scalar(&k, &path_opening_key);
		
    // Verify that we can extract the opening key from the file
    let extracted_k = extract_scalar(&path_opening_key);
    assert!(extracted_k == k, "The opening key in the file in not equal to the real opening key."); 
    
    let meta_opk = fs::metadata(&path_opening_key).expect("Error");
    let opk_size = meta_opk.len();
    print!("The opening key is generated and stored ({} bytes).\n", opk_size);
    	
    // Store the commitment in a file
    let _ = store_commit(&c, &path_commitment); 
        
    // Verify that we can extract the commitment from the file
    let extracted_c = extract_commit(l1.try_into().unwrap(), l2.try_into().unwrap(), &path_commitment); // Collect the stored commitment 
    assert!(extracted_c == c, "The commitment in the file in not equal to the real commitment."); // Verify that the real commitment and the collected commitment are the same
    
    let meta_com = fs::metadata(&path_commitment).expect("Error");
    let com_size = meta_com.len();
    print!("The commitment is generated and stored ({} bytes).\n", com_size);
    	
    // Store the proof of commitment
    let _ = store_proofcommit(&p_com, l1.try_into().unwrap(), l2.try_into().unwrap(), &path_proof_commitment);
    
    let meta_pcom = fs::metadata(&path_proof_commitment).expect("Error");
    let pcom_size = meta_pcom.len();
    print!("The proof of commitment is generated and stored ({} bytes).\n", pcom_size); 
 
    // Verify that we can extract the proof of commitment from the file
    let extracted_pcom = extract_proofcommit(l1.try_into().unwrap(), l2.try_into().unwrap(), &path_proof_commitment); // Collect the stored proof of commitment
    assert!(extracted_pcom == p_com, "The proof of commitment in the file in not equal to the real proof of commitment."); // Verify that the real proof of commitment and the collected proof of commitment are the same
}   	

// Generation and Storage of the signature of the commitment.
pub fn doctor_signature_generation_and_storage(path_set: &PathBuf, path_commitment: &PathBuf, path_signature: &PathBuf, path_doctor_public_key: &PathBuf, path_doctor_private_key: &PathBuf){

    let mut csrng = OsRng; // Random Number Generator based on the OS System (Crypto-Secure RNG)
   
    // Extract the setup from the file
    let set = extract_setup(&path_set);
    
    let l1 = set.l1;
    let l2 = set.l2;
   
    // Extract the commitment from the file
    let commitment = extract_commit(l1, l2, &path_commitment);
   
    // Sign phase:
    // Extract the public and private key from the file
    let doctor_public_key = extract_ristretto(&path_doctor_public_key);
    let doctor_private_key = extract_scalar(&path_doctor_private_key);
    
    // Sign the commitment using the private key of the Doctor
    let sig = sign(&mut csrng, commitment, RISTRETTO_BASEPOINT_POINT, doctor_public_key, doctor_private_key); // Signing Operation
		
    // Store the signature
    let _ = store_sig(&sig, &path_signature); 
 
    // Verify that we can extract the signature from the file
    let extracted_sig = extract_sig(&path_signature); // Collect the stored proof of commitment
    assert!(extracted_sig == sig, "The signature in the file in not equal to the real signature."); // Verify that the real signature and the collected signature are the same
    
    let meta = fs::metadata(&path_signature).expect("Error");
    let sig_size = meta.len();
    print!("The signature is created and stored ({} bytes).\n", sig_size);
}

// Phase executed by the Doctor.
pub fn doctor_phase(metadata: &Metadata, max_eps: Vec<f32>, path_data: &String, folder_eps: &String, folder_set: &String, folder_opening_key: &String, folder_commitment: &String, folder_proof_commitment: &String, folder_signature: &String, path_doctor_public_key: &PathBuf, path_doctor_private_key: &PathBuf){

    let start_doc_phase = Instant::now();

    // Parse metadata
    let name_data = &metadata.name;
    let column_index = metadata.col_index;
    let number_row = metadata.nb_row;
    let b = metadata.fl;
    let p = metadata.pr;
    let l2 = metadata.l2;

    let folder_eps_string = format!("{}/{}", folder_eps, name_data);
    let folder_eps = Path::new(&folder_eps_string);
    let folder_set_string = format!("{}/{}", folder_set, name_data);
    let folder_set = Path::new(&folder_set_string);
    let folder_opening_key_string = format!("{}/{}", folder_opening_key, name_data);
    let folder_opening_key = Path::new(&folder_opening_key_string);
    let folder_commitment_string = format!("{}/{}", folder_commitment, name_data);
    let folder_commitment = Path::new(&folder_commitment_string);
    let folder_proof_commitment_string = format!("{}/{}", folder_proof_commitment, name_data);
    let folder_proof_commitment = Path::new(&folder_proof_commitment_string);
    let folder_signature_string = format!("{}/{}", folder_signature, name_data);
    let folder_signature = Path::new(&folder_signature_string);
    let _ = fs::create_dir_all(folder_eps); // Create the folder of privacy budget.
    let _ = fs::create_dir_all(folder_set); // Create the folder of set.
    let _ = fs::create_dir_all(folder_opening_key); // Create the folder of the opening_key.
    let _ = fs::create_dir_all(folder_commitment); // Create the folder of the commitment.
    let _ = fs::create_dir_all(folder_proof_commitment); // Create the folder of the proof of commitment.
    let _ = fs::create_dir_all(folder_signature); // Create the folder of the signature.

    for row_index in 1..=number_row{	
        let path_eps = folder_eps.join(format!("eps_{}.txt", row_index)); 
        let path_set = folder_set.join(format!("set_{}.txt", row_index)); 
	let path_opening_key = folder_opening_key.join(format!("opening_key_{}.txt", row_index)); 
	let path_commitment = folder_commitment.join(format!("commitment_{}.txt", row_index));
	let path_proof_commitment = folder_proof_commitment.join(format!("proof_commitment_{}.txt", row_index));
	let path_signature = folder_signature.join(format!("signature_{}.txt", row_index));
		
	let l1 = doctor_precomputation(&name_data, row_index, max_eps[row_index-1], l2, &path_eps);
		
	doctor_setup_generation_and_storage(l1, l2, &path_set);
	doctor_commit_generation_and_storage(column_index, row_index, l1, l2, b, p, &path_data, &path_set, &path_opening_key, &path_commitment, &path_proof_commitment);
	doctor_signature_generation_and_storage(&path_set, &path_commitment, &path_signature, &path_doctor_public_key, &path_doctor_private_key);	
    }
    let duration_doc_phase = start_doc_phase.elapsed();
    print!("Doctor Phase took {:?} for {} data \n", duration_doc_phase, number_row);
}
	
