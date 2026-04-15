// Compute l2 the lenght of the data in binary
pub fn compute_l2(maximum: u32)->u32{
	if maximum.is_power_of_two(){
        return maximum.ilog2();
    }
    else{
    	return  maximum.ilog2()+1;
    }
}

// Compute l1 the parameter that determine the privacy budget epsilon
pub fn compute_l1(l2: u32, eps: f32)->u32{
	let l1 = ((2u32.pow(l2) as f32 +eps.exp()-1.0)/(eps.exp()-1.0)).log2().ceil(); // take a epsilon at most equal to eps.
    return l1 as u32
}

// Compute the privacy budget depending on l2 and l1
pub fn compute_eps(l2: u32, l1: u32)->f32{
	let eps = ((2u32.pow(l1) as f32 + 2u32.pow(l2) as f32 -1.0)/(2u32.pow(l1) as f32 -1.0)).ln();
	return eps
}
