use std::fs;
use std::path::Path;
use fs_extra::dir::{copy, CopyOptions};
use project::*;

fn main(){
	
    // Copy options.
    let mut options = CopyOptions::new();
    options.overwrite = true;
    options.copy_inside = false;
	
    println!("\nDoctor Phase\n");

    // Define the path to access to the patient data.
    let path_data = format!("doctor_space/data/heart_failure_clinical_records_dataset.csv"); 

    // Define the path to access to the privacy attending.
    let path_privacy = format!("doctor_space/data/privacy_moderate.csv"); 

    // Create the folder to store the public key of the Doctor in the Doctor space.
    let fldr_doc_pub_key_string: String = "doctor_space/doc_pub_key".to_string();
    let fldr_doc_pub_key = Path::new(&fldr_doc_pub_key_string);
    let _ = fs::create_dir_all(fldr_doc_pub_key);
    let path_doc_pub_key = fldr_doc_pub_key.join("doc_pub_key.txt");

    // Create the folder to store the private key of the Doctor in the Doctor space.
    // Notice that the Doctor private key is never disclosed to the hospital.
    let fldr_doc_priv_key_string: String = "doctor_space/doc_priv_key".to_string();
    let fldr_doc_priv_key = Path::new(&fldr_doc_priv_key_string);
    let _ = fs::create_dir_all(fldr_doc_priv_key);
    let path_doc_priv_key = fldr_doc_priv_key.join("doc_priv_key.txt");

    // Generation and storage of the public/private keys of the Doctor.
    doctor_keys_generation(&path_doc_pub_key, &path_doc_priv_key);
	
    // Define the folder to access to the original dataset in the Doctor space.
    let fldr_doc_data_string: String = "doctor_space/data".to_string();
    let fldr_doc_data = Path::new(&fldr_doc_data_string);

    // Define folder to store the privacy budget values in csv file in the Doctor space.
    let fldr_doc_eps_string: String = "doctor_space/privacy_budget".to_string();
    let fldr_doc_eps = Path::new(&fldr_doc_eps_string);
    let _ = fs::create_dir_all(fldr_doc_eps);
    let path_eps = format!("doctor_space/privacy_budget/privacy_budget.csv");

    // Define folder to store the setups in the Doctor space.  
    let fldr_doc_set_string: String = "doctor_space/set".to_string();
    let fldr_doc_set = Path::new(&fldr_doc_set_string);
    let _ = fs::create_dir_all(fldr_doc_set);

    // Define folder to store the opening keys in the Doctor space.
    let fldr_doc_opening_key_string: String = "doctor_space/opening_key".to_string();
    let fldr_doc_opening_key = Path::new(&fldr_doc_opening_key_string);
    let _ = fs::create_dir_all(fldr_doc_opening_key);

    // Define folder to store the commitments in the Doctor space.
    let fldr_doc_commitment_string: String = "doctor_space/commitment".to_string();
    let fldr_doc_commitment = Path::new(&fldr_doc_commitment_string);
    let _ = fs::create_dir_all(fldr_doc_commitment);

    // Define folder to store the proofs of validity of commitment in the Doctor space.
    let fldr_doc_proof_commitment_string: String = "doctor_space/proof_commitment".to_string();
    let fldr_doc_proof_commitment = Path::new(&fldr_doc_proof_commitment_string);
    let _ = fs::create_dir_all(fldr_doc_proof_commitment);

    // Define folder to store the signatures in the Doctor space.
    let fldr_doc_signature_string: String = "doctor_space/signature".to_string();
    let fldr_doc_signature = Path::new(&fldr_doc_signature_string);
    let _ = fs::create_dir_all(fldr_doc_signature);

    // Generate a metadata containing the name of each data, their range, their precision
    let prepro = doctor_preprocessing(&path_data);
    let column_number = prepro.0;
    let row_number = prepro.1;
    let dataset_metadata = prepro.2;

    // Phase executed by the Doctor to produce the setup, the opening key, the commitment, 
    // the proof of validity of commitment and the signature of the commitment.
    doctor_phase(column_number, row_number, &dataset_metadata, &path_data, &path_privacy, &path_eps, 
        &fldr_doc_set_string, &fldr_doc_opening_key_string, &fldr_doc_commitment_string,
        &fldr_doc_proof_commitment_string, &fldr_doc_signature_string, 
        &path_doc_pub_key, &path_doc_priv_key);
   
    // The Doctor sends the needed elements to the hospital: original data, privacy budget values, setups, 
    // opening keys, commitments, proofs of validity of commitments, signatures and doctor public key. 
    // Notice that the opening key and the patient data must be send via a secure channel.
    std::fs::create_dir_all("hospital_space").unwrap();
   
    copy(fldr_doc_data, "hospital_space", &options).unwrap();
    copy(fldr_doc_eps, "hospital_space", &options).unwrap();	
    copy(fldr_doc_set, "hospital_space", &options).unwrap();
    copy(fldr_doc_opening_key, "hospital_space", &options).unwrap();
    copy(fldr_doc_commitment, "hospital_space", &options).unwrap();
    copy(fldr_doc_proof_commitment, "hospital_space", &options).unwrap();
    copy(fldr_doc_signature, "hospital_space", &options).unwrap();
    copy(fldr_doc_pub_key, "hospital_space", &options).unwrap();
	
    println!("\nHospital Phase\n");

    // Define the path to access to the original dataset in the Hospital space.
    // Notice that the original dataset is never disclosed to the Researcher.
    let path_hosp_data = format!("hospital_space/data/heart_failure_clinical_records_dataset.csv");

    // Define the path to access to the privacy budget values in the Hospital space.
    let fldr_hosp_eps_string: String = "hospital_space/set".to_string();
    let fldr_hosp_eps = Path::new(&fldr_hosp_eps_string);
    let path_hosp_eps = format!("hospital_space/privacy_budget/privacy_budget.csv");

    // Define the path to access to the privacy budget values in the Hospital space.
    let fldr_hosp_set_string: String = "hospital_space/set".to_string();
    let fldr_hosp_set = Path::new(&fldr_hosp_set_string);

    // Define the path to access to the opening keys in the Hospital space.
    // Notice that the opening key is never disclosed to the Researcher.
    let fldr_hosp_opening_key_string: String = "hospital_space/opening_key".to_string();

    // Define the path to access to the commitment in the Hospital space.
    let fldr_hosp_commitment_string: String = "hospital_space/commitment".to_string();
    let fldr_hosp_commitment = Path::new(&fldr_hosp_commitment_string);

    // Define the path to access to the proof of validity of commitment in the Hospital space.
    let fldr_hosp_proof_commitment_string: String = "hospital_space/proof_commitment".to_string();
    let fldr_hosp_proof_commitment = Path::new(&fldr_hosp_proof_commitment_string);

    // Define the path to access to the privacy budget values in the Hospital space.
    let fldr_hosp_signature_string: String = "hospital_space/signature".to_string();
    let fldr_hosp_signature = Path::new(&fldr_hosp_signature_string);

    // Define the path to access to the public key of the Doctor in the Hospital space.
    let fldr_pub_key_string: String = "hospital_space/doc_pub_key".to_string();
    let fldr_pub_key = Path::new(&fldr_pub_key_string);
    let path_pub_key = fldr_pub_key.join("doc_pub_key.txt");

    // Define a folder to store the proof of validity of opening in the Hospital space.
    let fldr_hosp_proof_open_string: String = "hospital_space/proof_open".to_string();
    let fldr_hosp_proof_open = Path::new(&fldr_hosp_proof_open_string);
    let _ = fs::create_dir_all(fldr_hosp_proof_open);
	
    // Phase executed by the Hospital to verify the signature, the proof of commitment,
    // and to open the commitment on the patient data.
    hospital_phase(column_number, row_number, &dataset_metadata, &path_hosp_data, &path_hosp_eps, 
        &fldr_hosp_set_string, &fldr_hosp_opening_key_string, &fldr_hosp_commitment_string, 
        &fldr_hosp_proof_commitment_string, &fldr_hosp_proof_open_string, &fldr_hosp_signature_string, 
        &path_pub_key);
	
    println!("\nAnonymization Phase\n");	
    std::fs::create_dir_all("researcher_space").unwrap();
	
    // The Hospital sends the needed elements to the Researcher. 
    // The Researcher need to create seed according to the setup.
    copy(fldr_hosp_set, "researcher_space", &options).unwrap();
	
    // Define the path to access to the set in the Researcher space.
    let fldr_res_set_string: String = "researcher_space/set".to_string();
    
    // Define a folder to store the seed in the Researcher space.
    let fldr_res_seed_string: String = "researcher_space/pub_seed".to_string();
    let fldr_res_seed = Path::new(&fldr_res_seed_string);
    let _ = fs::create_dir_all(fldr_res_seed);
	
    // The Researcher generates random seeds according to the setups.
    researcher_gen_seed(column_number, row_number, &dataset_metadata, &fldr_res_set_string,
        &fldr_res_seed_string);
	
    // The Researcher sends the seeds to the Hospital.
    copy(fldr_res_seed, "hospital_space", &options).unwrap();
	
    // Define the path to access to the seeds in the Hospital space.
    let fldr_hosp_seed_string: String = "hospital_space/pub_seed".to_string();

    // Define a path to store the anonymized data in a csv file.
    let fldr_hosp_ano_data_string: String = "hospital_space/anonymized_data".to_string();
    let fldr_hosp_ano_data = Path::new(&fldr_hosp_ano_data_string);
    let _ = fs::create_dir_all(fldr_hosp_ano_data);
    let path_ano_data = format!("hospital_space/anonymized_data/heart_failure_clinical_records_dataset_anonymized.csv");
	
    // Define a folder to store the proof of opening.
    let fldr_hosp_proof_openldp_string: String = "hospital_space/proof_openldp".to_string();
    let fldr_hosp_proof_openldp = Path::new(&fldr_hosp_proof_openldp_string);
    let _ = fs::create_dir_all(fldr_hosp_proof_openldp);
	
    // Phase executed by the Hospital to produce the anonymized dataset and the proofs of correct anonymization.
    hospital_anonymization(column_number, row_number, &dataset_metadata, &fldr_hosp_set_string, 
        &fldr_hosp_opening_key_string, &fldr_hosp_commitment_string, &fldr_hosp_seed_string, 
        &fldr_hosp_proof_openldp_string, &path_ano_data);
	
   // The Hospital sends the needed elements to the Researcher: the anonymized data, the privacy budget values, 
   // the commitments, the proofs of validity of commitments, the proof of correct anonymization, the signature,
   // the public key of the doctor. 
    copy(fldr_hosp_ano_data, "researcher_space", &options).unwrap();
    copy(fldr_hosp_eps, "researcher_space", &options).unwrap();
    copy(fldr_hosp_commitment, "researcher_space", &options).unwrap();
    copy(fldr_hosp_proof_commitment, "researcher_space", &options).unwrap();
    copy(fldr_hosp_proof_openldp, "researcher_space", &options).unwrap();
    copy(fldr_hosp_signature, "researcher_space", &options).unwrap();
    copy(fldr_pub_key, "researcher_space", &options).unwrap();

    // Define the path to access to the anonymized data in the Researcher space.
    let path_ano_data = format!("researcher_space/anonymized_data/heart_failure_clinical_records_dataset_anonymized.csv");

    // Define the path to access to the privacy budget values in the Researcher space.
    let path_res_eps = format!("hospital_space/privacy_budget/privacy_budget.csv");

    // Define the path to access to the commitments in the Researcher space.
    let fldr_res_commitment_string: String = "researcher_space/commitment".to_string();

    // Define the path to access to the proofs of validity of commitments in the Researcher space.
    let fldr_res_proof_commitment_string: String = "researcher_space/proof_commitment".to_string();

    // Define the path to access to the proofs of correct anonymization in the Researcher space.
    let fldr_res_proof_openldp_string: String = "researcher_space/proof_openldp".to_string();

    // Define the path to access to the signature in the Researcher space.
    let fldr_res_signature_string: String = "researcher_space/signature".to_string();

    // Define the path to access to the public key of the Doctor in the Researcher space.
    let fldr_pub_key_string: String = "researcher_space/doc_pub_key".to_string();
    let fldr_pub_key = Path::new(&fldr_pub_key_string);
    let path_pub_key = fldr_pub_key.join("doc_pub_key.txt");
	
    println!("\nVerification Phase\n");
	
    researcher_verification(column_number, row_number, &dataset_metadata, &path_ano_data, &path_res_eps, &fldr_res_set_string, &fldr_res_commitment_string, &fldr_res_proof_commitment_string, &fldr_res_seed_string, &fldr_res_proof_openldp_string, &fldr_res_signature_string, &path_pub_key); 
}
