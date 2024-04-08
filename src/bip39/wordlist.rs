pub struct Wordlist<'a>(&'a [&'a str; 2048]);
pub const WORD_COUNT: usize = 2048;

mod english;

impl<'a> Wordlist<'a> {
    /// Create a new wordlist.
    pub fn new() -> &'a Self {
        &Wordlist(&english::WORDS)
    }

    /// Get a word from the wordlist.
    pub fn get(&self, index: usize) -> Option<&'a str> {
        self.0.get(index).copied()
    }

    /// Search for a word in the wordlist.
    pub fn get_index(&self, word: impl AsRef<str>) -> Option<usize> {
        self.0.binary_search(&word.as_ref()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist() {
        let wordlist = Wordlist::new();

        let word = "action";
        assert!(wordlist.get_index(word).is_some());

        let retrieved = wordlist.get(0).unwrap();
        assert_eq!(retrieved, "abandon");

        // assert the wordlist is 2048 words long
        assert_eq!(wordlist.0.len(), WORD_COUNT);
    }
}
