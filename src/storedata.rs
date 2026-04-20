use std::io;
use std::io::{IoSlice, Write, Read};
use std::fs::File;
use std::path::PathBuf;   
use curve25519_dalek::{scalar::Scalar, RistrettoPoint, ristretto::CompressedRistretto};
use crate::usefulfunction::*;
use crate::usefulstruct::*;

//Write a float in a file.
pub fn store_float(float: f32, name_file: &PathBuf) -> std::io::Result<()>{
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    file.write_all(&float.to_le_bytes())?;
    
    return Ok(())
}

// Extract a float located in a file.
pub fn extract_float(name_file: &PathBuf) -> f32{
    let mut file = File::open(name_file).expect("Impossible to open the file");

    let mut buffer = [0u8; std::mem::size_of::<f32>()];

    file.read_exact(&mut buffer).expect("Impossible to read the file");

    return f32::from_le_bytes(buffer)
}

// Write a type Vec<usize> in a file.
pub fn store_seed(vec_usize: Vec<Vec<usize>>, name_file: &PathBuf) -> io::Result<()>{

    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    for v in vec_usize{
    	for u in v{
        	file.write_all(&u.to_le_bytes())?;
        }
    }
    
    return Ok(())
}

// Extract the type Vec<usize> located in a file.
pub fn extract_seed(l1: usize, l2: usize, name_file: &PathBuf) -> Vec<Vec<usize>>{

    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut vec_seed_1: Vec<usize> = Vec::new();
    let mut vec_seed_2: Vec<usize> = Vec::new();
    for i in 0..l1{
    	vec_seed_1.push(buffer[i].into());
    }
    for i in l1..l1+l2{
    	vec_seed_2.push(buffer[i].into());
    }
    
    return vec![vec_seed_1, vec_seed_2];
}

// Write RistrettoPoint in a file:
pub fn store_ristretto(y: &RistrettoPoint, name_file: &PathBuf) -> io::Result<()>{

    let p: [u8; 32];
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    p = ((y).compress()).to_bytes();
    file.write_vectored(&[IoSlice::new(&p)])?;
    
    return Ok(())
}

// Extract the RistrettoPoint located in a file.
pub fn extract_ristretto(name_file: &PathBuf) -> RistrettoPoint{

    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut p: Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		p.push(array.clone());
    	}
    } 
    let y: RistrettoPoint = CompressedRistretto(p[0]).decompress().unwrap();
    
    return y
}

// Write Scalar in a file:
pub fn store_scalar(x: &Scalar, name_file: &PathBuf) -> io::Result<()>{

	let s: [u8; 32];
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    s = (x).to_bytes();
    file.write_vectored(&[IoSlice::new(&s)])?;
    
    return Ok(())
}

// Extract a Scalar located in a file.
pub fn extract_scalar(name_file: &PathBuf) -> Scalar{

    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut s : Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		s.push(array.clone());
    	}
    } 
    let x: Scalar = Scalar::from_bytes_mod_order(s[0]);
    
    return x
}

// Write the setup in a file:
pub fn store_setup(set: &Set, name_file: &PathBuf) -> io::Result<()>{
    let mut setup: Vec<[u8; 32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    match set{
    	Set{gen,g_,f_,h_,l1,l2} =>{
    	    setup.push(((gen).compress()).to_bytes());
    	    for i in 0..2{
    	        for j in 0..*l1{
    	            setup.push(((g_[i][j]).compress()).to_bytes()); 
    	        }
    	    }
    	    for i in 0..2{
    	        for j in 0..*l2{
    	            setup.push(((f_[i][j]).compress()).to_bytes());
    	        } 
    	    }
    	    for i in 0..2{
    	        for j in 0..*l2{
    	            setup.push(((h_[i][j]).compress()).to_bytes());
    	        } 
    	    }
            setup.push(usize_to_u8_array(*l1));
    	    setup.push(usize_to_u8_array(*l2));
        },
    }
    for i in 0..setup.len(){
        file.write_vectored(&[IoSlice::new(&setup[i])])?;
    }
    
    return Ok(())
} 

// Extract the setup located in a file:
pub fn extract_setup(name_file: &PathBuf) -> Set{

    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut setup: Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		setup.push(array.clone());
    	}
    }
    let l = setup.len();
    let l_1 = u8_array_to_usize(setup[l-2]);
    let l_2 = u8_array_to_usize(setup[l-1]);
    
    let generator = CompressedRistretto(setup[0]).decompress().unwrap();
    let mut gg: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut ff: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut hh: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut compt = 1;
    let mut g0: Vec<RistrettoPoint> = Vec::new();
    for j in compt..compt + l_1{
    	g0.push(CompressedRistretto(setup[j]).decompress().unwrap()); 
    }
    compt = compt + l_1;
    gg.push(g0);
    let mut g1: Vec<RistrettoPoint> = Vec::new();
    for j in compt..compt + l_1{
    	g1.push(CompressedRistretto(setup[j]).decompress().unwrap()); 
    }
    compt = compt + l_1;
    gg.push(g1);
    let mut f0: Vec<RistrettoPoint> = Vec::new();
    for j in compt..compt + l_2{
    	f0.push(CompressedRistretto(setup[j]).decompress().unwrap()); 
    }
    compt = compt + l_2;
    ff.push(f0);
    let mut f1: Vec<RistrettoPoint> = Vec::new();
    for j in compt..compt + l_2{
    	f1.push(CompressedRistretto(setup[j]).decompress().unwrap()); 
    }
    compt = compt + l_2;
    ff.push(f1);
    let mut h0: Vec<RistrettoPoint> = Vec::new();
    for j in compt..compt + l_2{
    	h0.push(CompressedRistretto(setup[j]).decompress().unwrap()); 
    }
    compt = compt + l_2;
    hh.push(h0);
    let mut h1: Vec<RistrettoPoint> = Vec::new();
    for j in compt..compt + l_2{
    	h1.push(CompressedRistretto(setup[j]).decompress().unwrap()); 
    }
    hh.push(h1); 
    
    return Set{gen: generator, g_: gg, f_: ff, h_: hh, l1: l_1, l2: l_2};
}

// Write the commitment in a file:
pub fn store_commit(c: &Commit, name_file: &PathBuf) -> io::Result<()>{

    let mut com: Vec<[u8; 32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    match c{
    	Commit{	pk, a1, a2, b0, b1 } =>{
    	    com.push(((pk).compress()).to_bytes());
    	    for i in 0..a1.len(){
    	        com.push(((a1[i]).compress()).to_bytes());		    
    	    }
    	    for i in 0..a2.len(){
    	        com.push(((a2[i]).compress()).to_bytes());		   
    	    }
    	    for i in 0..b0.len(){
    	        com.push(((b0[i]).compress()).to_bytes());		   
    	    }
    	    for i in 0..b1.len(){
    	        com.push(((b1[i]).compress()).to_bytes());		   
    	    }
        },
    }
    for i in 0..com.len(){
        file.write_vectored(&[IoSlice::new(&com[i])])?;
    }
    
    return Ok(())
}    
 
// Extract the commitment located in a file.
pub fn extract_commit(l1: usize, l2: usize, name_file: &PathBuf) -> Commit{

    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut com : Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		com.push(array.clone());
    	}
    }
    // pk
    let pubk = CompressedRistretto(com[0]).decompress().unwrap();
    let mut a_1: Vec<RistrettoPoint> = Vec::new();
    let mut a_2: Vec<RistrettoPoint> = Vec::new();
    let mut b_0: Vec<RistrettoPoint> = Vec::new();
    let mut b_1: Vec<RistrettoPoint> = Vec::new();
    
    // a1
    let mut compt = 1; 
    for i in compt..compt + l1{
    	a_1.push(CompressedRistretto(com[i]).decompress().unwrap());
    }
    compt = compt + l1;
    // a2
    for i in compt..compt + l2{
    	a_2.push(CompressedRistretto(com[i]).decompress().unwrap());
    }
    compt = compt + l2;
    // b0
    for i in compt..compt + l2{
    	b_0.push(CompressedRistretto(com[i]).decompress().unwrap());
    }
    compt = compt + l2;
    // b1
    for i in compt..compt + l2{
    	b_1.push(CompressedRistretto(com[i]).decompress().unwrap());
    }
    
    return Commit{pk: pubk, a1: a_1, a2: a_2, b0: b_0, b1: b_1};
}

// Write the proof of commitment in a file:
pub fn store_proofcommit(p: &ZeroKnowledgeProofCommit, l1: usize, l2: usize, name_file: &PathBuf) -> io::Result<()>{

    let mut proof: Vec<[u8; 32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    match p {
    	ZeroKnowledgeProofCommit{ proofa1, proofa2, proofb } =>{
	    for i in 0..l1{
    	    	match &proofa1[i]{ 
    	    	    ZeroKnowledgeProofA{commitment0,commitments,challenges,responses} =>{
    	    	        for j in 0..2{
    	    	            proof.push(((commitment0[j]).compress()).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push(((commitments[j]).compress()).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push((challenges[j]).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push((responses[j]).to_bytes());
    	    	        }
    	    	    }
    	        }
    	    }
    	    for i in 0..l2{
    	    	match &proofa2[i]{ 
    	    	    ZeroKnowledgeProofA{ commitment0, commitments, challenges, responses } => {
    	    	        for j in 0..2{
    	    	            proof.push(((commitment0[j]).compress()).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push(((commitments[j]).compress()).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push((challenges[j]).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push((responses[j]).to_bytes());
    	    	        }
    	    	    }
    	        }
    	    }
    	    for i in 0..l2{
    	    	match &proofb[i]{ 
    	    	    ZeroKnowledgeProofB{commitment0,commitments1,challenge1,response1,commitments2,challenge2,response2} =>{
    	    	      	for j in 0..2{
    	    	            proof.push(((commitment0[j]).compress()).to_bytes());
    	    	        }
    	    	        for j in 0..2{
    	    	            proof.push(((commitments1[j]).compress()).to_bytes());
    	    	        }
    	    	        proof.push((challenge1).to_bytes());
    	    	        proof.push((response1).to_bytes());
    	    	        for j in 0..2{
    	    	            proof.push(((commitments2[j]).compress()).to_bytes());
    	    	        }
    	    	        proof.push((challenge2).to_bytes());
    	    	        proof.push((response2).to_bytes());
    	    	        
    	    	    }
    	    	}
    	    }
    	}
    }	    
    for k in 0..proof.len(){
        file.write_vectored(&[IoSlice::new(&proof[k])])?;
    }
    
    return Ok(())
}

// Extract the proof of commitment located in a file.
pub fn extract_proofcommit(l1: usize, l2: usize, name_file: &PathBuf) -> ZeroKnowledgeProofCommit{

    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut p: Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		p.push(array.clone());
    	}
    }
    let mut compt = 0;
    
    // proofa1
    let mut proof_a1: Vec<ZeroKnowledgeProofA> = Vec::new();
    for _i in 0..l1{
        let mut r0: Vec<RistrettoPoint> = Vec::new();
    	let mut r: Vec<RistrettoPoint> = Vec::new();
    	let mut c: Vec<Scalar> = Vec::new();
    	let mut z: Vec<Scalar> = Vec::new();
    	r0.push(CompressedRistretto(p[compt]).decompress().unwrap());
        r0.push(CompressedRistretto(p[compt + 1]).decompress().unwrap());
    	compt = compt + 2; 
    	for j in compt..compt + 2{
    	    r.push(CompressedRistretto(p[j]).decompress().unwrap());
    	}
    	compt = compt + 2;
        for j in compt..compt + 2{
    	    c.push(Scalar::from_bytes_mod_order(p[j]));
    	}
    	compt = compt + 2;
        for j in compt..compt + 2{
    	    z.push(Scalar::from_bytes_mod_order(p[j]));
    	}
    	compt = compt + 2;
    	proof_a1.push(ZeroKnowledgeProofA{commitment0: r0, commitments: r, challenges: c, responses: z});  	
    } 
    compt = 8 * l1;
    // proofa2
    let mut proof_a2: Vec<ZeroKnowledgeProofA> = Vec::new();
    for _i in 0..l2{
        let mut r0: Vec<RistrettoPoint> = Vec::new();
    	let mut r: Vec<RistrettoPoint> = Vec::new();
    	let mut c: Vec<Scalar> = Vec::new();
    	let mut z: Vec<Scalar> = Vec::new();
    	r0.push(CompressedRistretto(p[compt]).decompress().unwrap());
    	r0.push(CompressedRistretto(p[compt+1]).decompress().unwrap());
    	compt = compt + 2;
    	for j in compt..compt + 2{
    	    r.push(CompressedRistretto(p[j]).decompress().unwrap());
    	}
    	compt = compt + 2;
        for j in compt..compt + 2{
    	    c.push(Scalar::from_bytes_mod_order(p[j]));
    	}
    	compt = compt + 2;
        for j in compt..compt + 2{
    	    z.push(Scalar::from_bytes_mod_order(p[j]));
    	}
    	compt = compt + 2;
    	proof_a2.push(ZeroKnowledgeProofA{commitment0: r0, commitments: r, challenges: c, responses: z});  	
    }
    compt = 8 * l1 + 8 * l2; 
    // proofb
    let mut proof_b: Vec<ZeroKnowledgeProofB> = Vec::new();
    for _i in 0..l2{
        let mut r0: Vec<RistrettoPoint> = Vec::new();
    	let mut r1: Vec<RistrettoPoint> = Vec::new();
    	let mut r2: Vec<RistrettoPoint> = Vec::new();
    	r0.push(CompressedRistretto(p[compt]).decompress().unwrap());
    	r0.push(CompressedRistretto(p[compt+1]).decompress().unwrap());
    	compt = compt + 2;
    	for j in compt..compt+2{
    	    r1.push(CompressedRistretto(p[j]).decompress().unwrap());
    	}
    	compt = compt + 2;
    	let c1 = Scalar::from_bytes_mod_order(p[compt]);
    	let z1 = Scalar::from_bytes_mod_order(p[compt + 1]);
    	compt = compt + 2;
        for j in compt..compt+2{
    	    r2.push(CompressedRistretto(p[j]).decompress().unwrap());
    	}
	compt = compt + 2;
    	let c2 = Scalar::from_bytes_mod_order(p[compt]);
    	let z2 = Scalar::from_bytes_mod_order(p[compt + 1]);
    	compt = compt + 2;
    	proof_b.push(ZeroKnowledgeProofB{commitment0: r0,commitments1: r1,challenge1: c1,response1: z1,commitments2: r2,challenge2: c2,response2: z2});  	
    }
    return ZeroKnowledgeProofCommit{proofa1: proof_a1, proofa2: proof_a2, proofb: proof_b };  
} 

// Write the proof of opening in a file:
pub fn store_proofopen(p: &ZeroKnowledgeProofOpen,name_file: &PathBuf) -> io::Result<()>{
    let mut proof: Vec<[u8; 32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    
    match p{
    	ZeroKnowledgeProofOpen{commitments, response} =>{
	    	for j in 0..commitments.len(){
    	    	proof.push(((commitments[j]).compress()).to_bytes());
    	    }
    	    proof.push((response).to_bytes());
    	}
    }	    
    for k in 0..proof.len(){
        file.write_vectored(&[IoSlice::new(&proof[k])])?;
    }
    return Ok(())
} 

// Extract the proof of opening located in a file.
pub fn extract_proofopen(name_file: &PathBuf) -> ZeroKnowledgeProofOpen{
    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut p: Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		p.push(array.clone());
    	}
    }
    let mut r: Vec<RistrettoPoint> =  Vec::new();
    for j in 0..2{
    	r.push(CompressedRistretto(p[j]).decompress().unwrap());
    }
    let z = Scalar::from_bytes_mod_order(p[2]);
    return ZeroKnowledgeProofOpen{commitments: r, response: z};
}

// Write the proof of opening with LDP in a file:
pub fn store_proofopenldp(p: &ZeroKnowledgeProofOpenLDP1, name_file: &PathBuf) -> io::Result<()>{
    let mut proof: Vec<[u8; 32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?; 
    match p{ 
    	ZeroKnowledgeProofOpenLDP1{y_1_p, proof_openldp_0} 
    		=>{ proof.push(((y_1_p).compress()).to_bytes());
    		
    			match proof_openldp_0{
    			ZeroKnowledgeProofOpenLDP0{commitments0, challenge0, response0, commitments1, challenge1, responses1} 
    				=>{	
	    				for j in 0..commitments0.len(){
    	    				proof.push(((commitments0[j]).compress()).to_bytes());
    					}
    	   			 	proof.push((challenge0).to_bytes());
    	    			proof.push((response0).to_bytes());
    	    			for j in 0..commitments1.len(){
    	    				proof.push(((commitments1[j]).compress()).to_bytes());
    	    			}
    	   				proof.push((challenge1).to_bytes());
    	    			for j in 0..responses1.len(){
    	    				proof.push((responses1[j]).to_bytes());
    	    			}
    				}
    		}
    	}	
    }    
    for k in 0..proof.len(){
        file.write_vectored(&[IoSlice::new(&proof[k])])?;
    }
    return Ok(())
} 

// Extract the proof of opening located in a file.
pub fn extract_proofopenldp(name_file: &PathBuf) -> ZeroKnowledgeProofOpenLDP1{
    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut p : Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		p.push(array.clone());
    	}
    }
    let mut r0: Vec<RistrettoPoint> =  Vec::new();
    let mut r1: Vec<RistrettoPoint> =  Vec::new();
    let mut z1: Vec<Scalar> =  Vec::new();
    let y1_p: RistrettoPoint = CompressedRistretto(p[0]).decompress().unwrap();
    for j in 1..4{
    	r0.push(CompressedRistretto(p[j]).decompress().unwrap());
    }
    let c0 = Scalar::from_bytes_mod_order(p[4]);
    let z0 = Scalar::from_bytes_mod_order(p[5]);
    for j in 6..12{
    	r1.push(CompressedRistretto(p[j]).decompress().unwrap());
    }
    let c1 = Scalar::from_bytes_mod_order(p[12]);
    for j in 13..15{
    	z1.push(Scalar::from_bytes_mod_order(p[j]));
    }
    let proof_openldp0 = ZeroKnowledgeProofOpenLDP0{commitments0: r0, challenge0: c0, response0: z0, commitments1: r1, challenge1: c1, responses1: z1};
    return ZeroKnowledgeProofOpenLDP1{y_1_p: y1_p, proof_openldp_0: proof_openldp0};
}

// Write the signature in a file
pub fn store_sig(s: &Signature, name_file: &PathBuf) -> io::Result<()>{
    let mut sig: Vec<[u8; 32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open(name_file)?;
    match s{
    	Signature{r,z} =>{
    	    sig.push(((r).compress()).to_bytes());
    	    sig.push((z).to_bytes());
    	}
    }	    
    for k in 0..sig.len(){
        file.write_vectored(&[IoSlice::new(&sig[k])])?;
    }
    return Ok(())
} 

// Extract the signature located in a file.
pub fn extract_sig(name_file: &PathBuf) -> Signature{
    let mut buffer = Vec::new();
    let file = File::open(name_file); 
    let _= file.expect("Impossible to open the file").read_to_end(&mut buffer); 
    let mut s: Vec<[u8; 32]> = Vec::new();
    let mut array = [0u8; 32];
    for i in 0..buffer.len(){
    	array[i % 32] = buffer[i];
    	if i % 32 == 31 && i > 0{
    		s.push(array.clone());
    	}
    }
    let rr: RistrettoPoint = CompressedRistretto(s[0]).decompress().unwrap();
    let zz: Scalar = Scalar::from_bytes_mod_order(s[1]);
    return Signature{r: rr, z: zz};
}
