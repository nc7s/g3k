use {
	std::thread::spawn,
	pgp::{
		composed::{
			KeyType,
			key::{SecretKey, SecretKeyParamsBuilder},
		},
		types::KeyTrait,
	},
	chrono::{
		DateTime, Duration,
		offset::Utc,
	},
	argh::FromArgs,
	hex::ToHex,
	num_cpus::get_physical,
	anyhow::{Context, Result},
};

#[derive(Debug, Clone)]
#[derive(FromArgs)]
/// Generate Good-looking GPG Keys
struct CliArgs {
	/// number of threads to use, defaults to number of physical CPU cores
	#[argh(option, default = "get_physical()")]
	threads: usize,
	/// max backflow of one iteration, in seconds, defaults to 30 days equivalent
	#[argh(option, default = "86400 * 30")]
	max_backflow: usize,
	/// file name to save key to, defaults to FINGERPRINT.key in working directory
	#[argh(option, default = "String::new()")]
	save_path: String,
	/// don't save, output armored key certifitace to stdout; off by default
	#[argh(switch)]
	no_save: bool,
	/// user ID
	#[argh(option, default = "String::from(\"G3K\")")]
	uid: String,
	/// desired fingerprint / Key ID suffix
	#[argh(positional)]
	suffix: String,
}

#[derive(Clone)]
struct Builder {
	kb: SecretKeyParamsBuilder,
	ct: DateTime<Utc>,
	k: Option<SecretKey>,
}

impl Builder {
	/// Create a builder. Hard coded to Cv25519, may provide options later.
	fn new (uid: &str) -> Self {
		let mut pgp_builder = SecretKeyParamsBuilder::default();
		pgp_builder
			.key_type(KeyType::EdDSA)
			.can_create_certificates(true)
			.can_sign(true)
			.primary_user_id(uid.into());
		Self {
			kb: pgp_builder,
			ct: Utc::now(),
			k: None,
		}
	}

	fn gen(&mut self) -> Result<()> {
		self.kb.created_at(self.ct);
		match self.kb.build() {
			Ok(sk) => {
				self.k = Some(sk.generate()?);
				Ok(())
			},
			Err(e) => anyhow::bail!(e)
		}
	}

	/// "Flow" back creation time for one second. This is faster than generating a whole new key.
	fn backflow(&mut self) {
		self.ct = self.ct - Duration::seconds(1);
	}

	fn fingerprint(&self) -> Result<String> {
		match &self.k {
			Some(key) => Ok(key.fingerprint().encode_hex::<String>()),
			None => anyhow::bail!("no key generated yet"),
		}
	}

	fn armored(&self) -> Result<String> {
		self.k.as_ref().unwrap().clone()
			.sign(String::new)?
			.to_armored_string(None).context("armoring failed")
	}
}

fn main() -> Result<()> {
	let args: CliArgs = argh::from_env();
	println!("Looking for suffix \"{}\" with uid \"{}\", {} threads, max backflow {} seconds{}",
		&args.suffix, &args.uid, &args.threads, &args.max_backflow, if args.no_save { ", no save" } else { "" });
	let suffix = args.suffix.to_lowercase();
	let (sender, receiver) = crossbeam_channel::unbounded();
	for _ in 0..args.threads {
		let args = args.clone();
		let sender = sender.clone();
		let suffix = suffix.clone();
		spawn(move || -> Result<()> {
			let mut iterations: usize = 0;
			loop {
				let mut builder = Builder::new(&args.uid);
				let mut backflow: usize = 0;
				while backflow < args.max_backflow {
					builder.backflow();
					builder.gen()?;
					let fp = builder.fingerprint()?;
					if fp.ends_with(&suffix) {
						sender.send((builder.clone(), iterations))?;
					}
					backflow += 1;
					iterations += 1;
				}
			}
		});
	}
	let (result, iterations): (Builder, usize) = receiver.recv()?;
	println!("Found one after approx. {} iterations", iterations * args.threads);
	println!("Fingerprint: {}", result.fingerprint()?);
	if args.no_save {
		println!("Private key:\n\n{}\n", result.armored()?);
	} else {
		let save_path = if args.save_path.is_empty() {
			format!("{}.key", result.fingerprint()?)
		} else { args.save_path };
		std::fs::write(&save_path, result.armored()?)?;
		println!("Written to {}", &save_path);
	}
	Ok(())
}
