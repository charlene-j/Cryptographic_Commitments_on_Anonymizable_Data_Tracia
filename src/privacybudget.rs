// Compute l2 the lenght of the data in binary
pub fn compute_l2(maximum: u32) -> u32 {
    if maximum == 0 {
        return 0;
    }

    maximum.ilog2() + 1
}

// Compute l1 the parameter that determine the privacy budget epsilon
pub fn compute_l1(l2: u32, eps: f64)->u32{
	let l1: f64;
    if eps == 0f64{
        l1 = 0f64;
    } 
    else{
        l1 = ((2u32.pow(l2) as f64 +eps.exp()-1.0)/(eps.exp()-1.0)).log2().ceil(); // take a epsilon at most equal to eps.
    }
    return l1 as u32
}

// Compute the privacy budget depending on l2 and l1
pub fn compute_eps(l2: u32, l1: u32)->f64{
	let eps = ((2u32.pow(l1) as f64 + 2u32.pow(l2) as f64 -1.0)/(2u32.pow(l1) as f64 -1.0)).ln();
	return eps
}
