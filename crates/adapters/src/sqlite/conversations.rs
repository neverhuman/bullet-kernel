//! Complete conversation history is committed through the owned command transaction.

mod admission;
mod history;
mod reads;
mod validation;

#[cfg(test)]
mod tests;

pub(super) use admission::submit;
pub(super) use validation::verify;
