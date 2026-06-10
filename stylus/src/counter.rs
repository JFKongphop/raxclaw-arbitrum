use stylus_sdk::{alloy_primitives::U256, prelude::*};

sol_storage! {
    #[entrypoint]
    pub struct Counter {
        uint256 number;
    }
}

#[public]
impl Counter {
  pub fn number(&self) -> U256 {
    self.number.get()
  }

  pub fn set_number(&mut self, new_number: U256) {
    self.number.set(new_number);
  }

  pub fn mul_number(&mut self, new_number: U256) {
    self.number.set(new_number * self.number.get());
  }

  pub fn add_number(&mut self, new_number: U256) {
    self.number.set(new_number + self.number.get());
  }

  pub fn increment(&mut self) {
    let number = self.number.get();
    self.set_number(number + U256::from(1));
  }

  #[payable]
  pub fn add_from_msg_value(&mut self) {
    let number = self.number.get();
    self.set_number(number + self.vm().msg_value());
  }
}
