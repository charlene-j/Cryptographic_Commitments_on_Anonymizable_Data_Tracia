use curve25519_dalek::{scalar::Scalar, RistrettoPoint};

//
pub struct Metadata{ 
    pub name: String, 
    pub col_index: usize, 
    pub nb_row: usize,
    pub max_discret_data: u32, 
    pub fl: bool, 
    pub pr: u32,
    pub l2: u32
}

// Definition of the structure for the setup set:
#[derive(Clone,Debug,PartialEq)]
pub struct Set{ 
    pub gen: RistrettoPoint, 
    pub g_: Vec<Vec<RistrettoPoint>>, 
    pub f_: Vec<Vec<RistrettoPoint>>, 
    pub h_: Vec<Vec<RistrettoPoint>>, 
    pub l1: usize, 
    pub l2: usize 
}
 
// Definition of the structure for the commitment:
#[derive(Clone,Debug,PartialEq)]
pub struct Commit{ 
    pub pk: RistrettoPoint, 
    pub a1: Vec<RistrettoPoint>, 
    pub a2: Vec<RistrettoPoint>, 
    pub b0: Vec<RistrettoPoint>, 
    pub b1: Vec<RistrettoPoint>
}

// Definition of the structure for the zero-knowledge proofs "pi_{A_1}" and "pi_{A_2}":
#[derive(Debug, PartialEq)]
pub struct ZeroKnowledgeProofA{
    pub commitment0: Vec<RistrettoPoint>,
    pub commitments: Vec<RistrettoPoint>,
    pub challenges: Vec<Scalar>,
    pub responses: Vec<Scalar>
}

// Definition of the structure for the zero-knowledge proofs "pi_B":
#[derive(Debug,PartialEq)]
pub struct ZeroKnowledgeProofB{
    pub commitment0: Vec<RistrettoPoint>,
    pub commitments1: Vec<RistrettoPoint>,
    pub challenge1: Scalar,
    pub response1: Scalar,
    pub commitments2: Vec<RistrettoPoint>,
    pub challenge2: Scalar,
    pub response2: Scalar
}

// Definition of the structure for the zero-knowledge proofs in the algorithm "Commit":
#[derive(Debug,PartialEq)]
pub struct ZeroKnowledgeProofCommit{
    pub proofa1: Vec<ZeroKnowledgeProofA>,
    pub proofa2: Vec<ZeroKnowledgeProofA>,
    pub proofb: Vec<ZeroKnowledgeProofB>
}

// Definition of the structure for the zero-knowledge proofs in the algorithm "Open":
#[derive(Debug,PartialEq)]
pub struct ZeroKnowledgeProofOpen{
    pub commitments: Vec<RistrettoPoint>,
    pub response: Scalar
}

// Definition of the structure for the zero-knowledge proofs in the algorithm "OpenLDP":
#[derive(Debug,PartialEq)]
pub struct ZeroKnowledgeProofOpenLDP1{
	pub y_1_p: RistrettoPoint,
    pub proof_openldp_0: ZeroKnowledgeProofOpenLDP0,
}

// Definition of the structure for the zero-knowledge proofs in the algorithm "OpenLDP":
#[derive(Debug,PartialEq)]
pub struct ZeroKnowledgeProofOpenLDP0{
    pub commitments0: Vec<RistrettoPoint>,
    pub challenge0: Scalar,
    pub response0: Scalar,
    pub commitments1: Vec<RistrettoPoint>,
    pub challenge1: Scalar,
    pub responses1: Vec<Scalar>
}

// Definition of the structure for the signature:
#[derive(Debug, PartialEq)]
pub struct Signature{
    pub r: RistrettoPoint,
    pub z: Scalar
}
