#![allow(unused_imports)]
#![allow(unused_variables)]
use rand::{Rng, thread_rng};
use rand_core::{CryptoRng, RngCore, OsRng}; 
use sha2::{Sha512,Digest}; 
use curve25519_dalek::{scalar::Scalar, RistrettoPoint, traits::Identity, constants::RISTRETTO_BASEPOINT_POINT, constants::RISTRETTO_BASEPOINT_TABLE, ristretto::CompressedRistretto};
use csv::Reader;
use crate::import_data_u32;
use crate::import_data_f32;

// Compute the maximum value 
pub fn compute_max(path_file: &String, column_index: usize, number_row: usize, b: bool, p: u32) -> u32{

	let rdr = Reader::from_path(&path_file);
	let mut max = 0u32;
	let mut data: u32;
	for row_index in 1..=number_row {
		if b == false{
			data = import_data_u32(&path_file, column_index, row_index).expect("Impossible to import the data");
			if max < data {
				max = data;
			}
		}
		else { 
			data = import_data_f32(&path_file, column_index, row_index, p).expect("Impossible to import the data");
			if max < data {
				max = data;
			}
		}
	}
	
	return max
}

// Generate a random Scalar element:
pub fn rand_scalar<T: CryptoRng + RngCore>(rng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 64];
    rng.fill_bytes(&mut scalar_bytes);
    
    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
}
   
// Generate a random RistrettoPoint element:
pub fn rand_element<T: CryptoRng + RngCore>(rng: & mut T) -> RistrettoPoint{ 
  
    let r = rand_scalar(rng);
    let g = &r * RISTRETTO_BASEPOINT_TABLE;
    
    return g;
}

// Generate a random vector of bit of size l:
pub fn rand_bitstring(l: usize) -> Vec<usize>{

    let mut v: Vec<usize> = Vec::new();
    let mut rng = thread_rng(); 
    for _i in 0..l{
        if rng.gen_bool(0.5) == true{
            v.push(0);      
        }
       	else {
	    	v.push(1); 
        }
    }
    
    return v;
}

// Compute the sum of Scalar element:
pub fn sum_scalar(s: Vec<Scalar>) -> Scalar{
	
    let mut sum = convert_scalar([0u8; 32]);
    for i in 0..s.len(){
    	sum = sum + s[i];  
    }
    
    return sum;
}

// Compute the sum of RistrettoPoint:
pub fn sum_ristretto(r: Vec<RistrettoPoint>) -> RistrettoPoint{
    let mut sum = RistrettoPoint::identity();
    for i in 0..r.len(){
    	sum = sum + r[i];  
    }
    
    return sum;
}

// Convert a u32 in binary:
pub fn convert_u32_in_binary(a: u32, l_2: u32) -> Vec<usize>{  
    let mut vec: Vec<usize> = Vec::new();
    let mut aa= a;
    while aa != 0{
		vec.push((aa%2).try_into().unwrap());
		aa = aa/2;
    }
    while vec.len() < l_2.try_into().unwrap(){
    	vec.push(0);
    }
    
    return vec
}

// Convert a u32 in binary:
pub fn convert_binary_in_u32(u: Vec<usize>, l_2: u32) -> u32{  
    let mut a: u32 = 0u32;
    for i in 0..l_2{
    	if u[i as usize] == 1{
   			a = a + 2u32.pow(i);
    	}
    }
    
    return a
}

// Convert a [u8; 32] in Scalar:
pub fn convert_scalar(a: [u8; 32]) -> Scalar{  
 
    let s = Scalar::from_bytes_mod_order(a);
    
    return s
}

// Convert a usize to an array [u8; 32]:
pub fn usize_to_u8_array(u: usize) -> [u8; 32]{

    let mut array: [u8; 32] = [0u8;32];
    let bytes = u.to_le_bytes();
    for i in 0..bytes.len(){
        array[i] = bytes[i];
    }
    
    return array;
}

// Convert an array [u8; 32] to a usize:
pub fn u8_array_to_usize(array: [u8; 32]) -> usize{

    let bytes = &array[0..8]; 
    let u = usize::from_le_bytes(bytes.try_into().expect("Impossible to convert")); 
    
    return u;
}

// Hash a vector of bytes:
pub fn hash(digest: Vec<[u8;32]>) -> Scalar{

    let mut hasher = <Sha512 as Digest>::new();
    for d in digest {
        hasher.update(d.as_slice());
    }
    let result = hasher.finalize();
    
    Scalar::from_bytes_mod_order_wide(&result.into())
}
