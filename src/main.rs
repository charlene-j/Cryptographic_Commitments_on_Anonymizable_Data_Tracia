use std::fs;
use std::path::Path;
use fs_extra::dir::{copy, CopyOptions};
use project::*;

fn main(){
	
    // Copy options.
    let mut options = CopyOptions::new();
    options.overwrite = true;
    options.copy_inside = false;
	
	// Define some privacy budget (the lower the value, the better the confidentiality, but the lower the utility).
    let eps_highly_sensitive: f32 = 0.5;
    let eps_sensitive: f32 = 0.73;
    let eps_less_sensitive: f32 = 1.11;
	
	println!("\nDoctor Phase\n");
	
	// Pretreatment of the data.
    /*let path_data = format!("doctor_space/data/heart_failure_clinical_records_dataset.csv"); // Define the path to access to the patient data.
	let name_data = "serum_creatinine".to_string();
	let column_index = 7;
	let number_row = 299;
	let b = true; // b == true if the data is a floating, b == false else.
	let precision = 2u32; // the precision correspond to the number of values after the commas if b == true.
	let max_data = compute_max(&path_data, column_index, number_row, b, precision); // The max can also be fixed in advance in accordance to the maximum of value that can be taken by the data.
	println!("Maximum value of the discretized data: {}", max_data);
	let l2 = compute_l2(max_data); // l2 correspond to the ceiling of the base-2 logarithm of max_data. l2 >= log_2(max_data).*/
	let path_data = format!("doctor_space/data/heart_failure_clinical_records_dataset.csv"); // Define the path to access to the patient data.
	let name_data = "age".to_string();
	let column_index = 0;
	let number_row = 299;
	let b = false; // b == true if the data is a floating, b == false else.
	let precision = 0u32; // the precision correspond to the number of values after the commas if b == true.
	let max_data = compute_max(&path_data, column_index, number_row, b, precision); // The max can also be fixed in advance in accordance to the maximum of value that can be taken by the data.
	println!("Maximum value of the discretized data: {}", max_data);
	let l2 = compute_l2(max_data); // l2 correspond to the ceiling of the base-2 logarithm of max_data. l2 >= log_2(max_data).
	
	let metadata = Metadata{name: name_data.clone(), col_index: column_index, nb_row: number_row, max_discret_data: max_data, fl: b, pr: precision, l2: l2};
	
	// Define different privacy budget for the individuals.
	let mut max_eps: Vec<f32> = Vec::with_capacity(299); //The exact value of the confidentiality budget will be determined later, based on the value of l1, in order to obtain a confidentiality budget at most equal to max_eps.
	for _ in 0..100{
		max_eps.push(eps_highly_sensitive);
	}
	for _ in 0..100{
		max_eps.push(eps_sensitive);
	}
	for _ in 0..99{
		max_eps.push(eps_less_sensitive);
	}

	// Create the folder to store the public/private keys of the doc.
	let fldr_doc_pub_key_string: String = "doctor_space/doc_pub_key".to_string();
	let fldr_doc_pub_key = Path::new(&fldr_doc_pub_key_string);
	let _ = fs::create_dir_all(fldr_doc_pub_key);
	let path_doc_pub_key = fldr_doc_pub_key.join("doc_pub_key.txt");
	let fldr_doc_priv_key_string: String = "doctor_space/doc_priv_key".to_string();
	let fldr_doc_priv_key = Path::new(&fldr_doc_priv_key_string);
	let _ = fs::create_dir_all(fldr_doc_priv_key);
	let path_doc_priv_key = fldr_doc_priv_key.join("doc_priv_key.txt");

	// Generation and storage of the public/private keys by the doctor.
	doctor_keys_generation(&path_doc_pub_key, &path_doc_priv_key);
	
	// Define folders to store the produced values by the doctor.
	let fldr_doc_data_string: String = "doctor_space/data".to_string();
	let fldr_doc_data = Path::new(&fldr_doc_data_string);
	let fldr_doc_set_string: String = "doctor_space/set".to_string();
	let fldr_doc_set = Path::new(&fldr_doc_set_string);
	let _ = fs::create_dir_all(fldr_doc_set);
	let fldr_doc_opening_key_string: String = "doctor_space/opening_key".to_string();
	let fldr_doc_opening_key = Path::new(&fldr_doc_opening_key_string);
	let _ = fs::create_dir_all(fldr_doc_opening_key);
	let fldr_doc_commitment_string: String = "doctor_space/commitment".to_string();
	let fldr_doc_commitment = Path::new(&fldr_doc_commitment_string);
	let _ = fs::create_dir_all(fldr_doc_commitment);
	let fldr_doc_proof_commitment_string: String = "doctor_space/proof_commitment".to_string();
	let fldr_doc_proof_commitment = Path::new(&fldr_doc_proof_commitment_string);
	let _ = fs::create_dir_all(fldr_doc_proof_commitment);
	let fldr_doc_signature_string: String = "doctor_space/signature".to_string();
	let fldr_doc_signature = Path::new(&fldr_doc_signature_string);
	let _ = fs::create_dir_all(fldr_doc_signature);
	
	// Phase executed by the doctor to produce the setup, the opening key, the commitment, the proof of correct commitment and the signature of the commitment.
	doctor_phase(&metadata, max_eps, &path_data, &fldr_doc_set_string, &fldr_doc_opening_key_string, &fldr_doc_commitment_string, &fldr_doc_proof_commitment_string, &fldr_doc_signature_string, &path_doc_pub_key, &path_doc_priv_key);
   
    // The doctor sends the needed elements to the hospital (simulated by copying); Notice that the opening key and the patient data must be send via a secure channel.
    std::fs::create_dir_all("hospital_space").unwrap();
   
	copy(fldr_doc_data, "hospital_space", &options).unwrap();
	copy(fldr_doc_set, "hospital_space", &options).unwrap();
	copy(fldr_doc_opening_key, "hospital_space", &options).unwrap();
	copy(fldr_doc_commitment, "hospital_space", &options).unwrap();
	copy(fldr_doc_proof_commitment, "hospital_space", &options).unwrap();
	copy(fldr_doc_signature, "hospital_space", &options).unwrap();
	copy(fldr_doc_pub_key, "hospital_space", &options).unwrap();
	
	println!("\nHospital Phase\n");
	
	// Define the path of the elements stored by the hospital.
	let fldr_pub_key_string: String = "hospital_space/doc_pub_key".to_string();
	let fldr_pub_key = Path::new(&fldr_pub_key_string);
	let path_pub_key = fldr_pub_key.join("doc_pub_key.txt");
	let fldr_hosp_set_string: String = "hospital_space/set".to_string();
	let fldr_hosp_opening_key_string: String = "hospital_space/opening_key".to_string();
	let fldr_hosp_commitment_string: String = "hospital_space/commitment".to_string();
	let fldr_hosp_commitment = Path::new(&fldr_hosp_commitment_string);
	let fldr_hosp_proof_commitment_string: String = "hospital_space/proof_commitment".to_string();
	let fldr_hosp_proof_commitment = Path::new(&fldr_hosp_proof_commitment_string);
	let fldr_hosp_signature_string: String = "hospital_space/signature".to_string();
	let fldr_hosp_signature = Path::new(&fldr_hosp_signature_string);
	let path_data = format!("hospital_space/data/heart_failure_clinical_records_dataset.csv");
	
	// Define a folder to store the proof of opening.
	let fldr_hosp_proof_open_string: String = "hospital_space/proof_open".to_string();
	let fldr_hosp_proof_open = Path::new(&fldr_hosp_proof_open_string);
	let _ = fs::create_dir_all(fldr_hosp_proof_open);
	
	// Phase executed by the hospital to verify the signature, the proof of commitment, and to open the commitment on the patient data.
	hospital_phase(&metadata, &path_data, &fldr_hosp_set_string, &fldr_hosp_opening_key_string, &fldr_hosp_commitment_string, &fldr_hosp_proof_commitment_string, &fldr_hosp_proof_open_string, &fldr_hosp_signature_string, &path_pub_key);
	
	println!("\nAnonymization Phase\n");
	
	std::fs::create_dir_all("researcher_space").unwrap();
	
	// Define the path to access to the set for the researcher.
	let fldr_res_set_string: String = "researcher_space/set".to_string();
	
	// The hospital sends the needed elements to the researcher (the researcher need to create seed according to l1 and l2).
	
	copy("hospital_space/set", "researcher_space", &options).unwrap();
	
	// Define a folder to store the seed.
	let fldr_res_seed_string: String = "researcher_space/pub_seed".to_string();
	let fldr_res_seed = Path::new(&fldr_res_seed_string);
	let _ = fs::create_dir_all(fldr_res_seed);
	
	// The researcher generates a random seed.
	researcher_gen_seed(&name_data, number_row, &fldr_res_set_string, &fldr_res_seed_string);
	
	// The researcher sends the seed to the hospital.
	copy(fldr_res_seed, "hospital_space", &options).unwrap();
	
	// Define the path to access to the seed for the hospital.
	let fldr_hosp_seed_string: String = "hospital_space/pub_seed".to_string();

	let fldr_hosp_ano_data_string: String = "hospital_space/anonymized_data".to_string();
	let fldr_hosp_ano_data = Path::new(&fldr_hosp_ano_data_string);
	let _ = fs::create_dir_all(fldr_hosp_ano_data);
	
	// Define a path to store the anonymized data in a csv file.
	let path_ano_data = format!("hospital_space/anonymized_data/heart_failure_clinical_records_dataset_{}_anonymized.csv", &name_data);
	
	// Define a folder to store the proof of opening.
	let fldr_hosp_proof_openldp_string: String = "hospital_space/proof_openldp".to_string();
	let fldr_hosp_proof_openldp = Path::new(&fldr_hosp_proof_openldp_string);
	let _ = fs::create_dir_all(fldr_hosp_proof_openldp);
	
	// Phase executed by the hospital to produce the anonymized patient data and the proof of correct anonymization.
	hospital_anonymization(&metadata, &fldr_hosp_set_string, &fldr_hosp_opening_key_string, &fldr_hosp_commitment_string, &fldr_hosp_seed_string, &fldr_hosp_proof_openldp_string, &path_ano_data);
	
	// The hospital sends the needed elements to the researcher.
	copy(fldr_pub_key, "researcher_space", &options).unwrap();
	copy(fldr_hosp_commitment, "researcher_space", &options).unwrap();
	copy(fldr_hosp_proof_commitment, "researcher_space", &options).unwrap();
	copy(fldr_hosp_proof_openldp, "researcher_space", &options).unwrap();
	copy(fldr_hosp_ano_data, "researcher_space", &options).unwrap();
	copy(fldr_hosp_signature, "researcher_space", &options).unwrap();
	
	let fldr_pub_key_string: String = "researcher_space/doc_pub_key".to_string();
	let fldr_pub_key = Path::new(&fldr_pub_key_string);
	let path_pub_key = fldr_pub_key.join("doc_pub_key.txt");
	let fldr_res_commitment_string: String = "researcher_space/commitment".to_string();
	let fldr_res_proof_commitment_string: String = "researcher_space/proof_commitment".to_string();
	let fldr_res_proof_openldp_string: String = "researcher_space/proof_openldp".to_string();
	let fldr_res_signature_string: String = "researcher_space/signature".to_string();
	let path_ano_data = format!("researcher_space/anonymized_data/heart_failure_clinical_records_dataset_{}_anonymized.csv", &name_data);
	
	println!("\nVerification Phase\n");
	
	researcher_verification(&metadata, &fldr_res_set_string, &fldr_res_commitment_string, &fldr_res_proof_commitment_string, &fldr_res_seed_string, &fldr_res_proof_openldp_string, &fldr_res_signature_string, &path_pub_key, &path_ano_data);  	
}
