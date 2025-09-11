use clap::{Parser, Subcommand};

/// Main args of tlv-tool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Tool {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Encodes TLV-stream into hex.
    Encode {
        /// Json encoded data to encode into hex TLV-stream.
        data: String,
    },
    /// Decodes TLV-stream from hex.
    Decode {
        /// Hex-encoded String.
        data: String,
    },
}

fn main() {
    let tool = Tool::parse();

    match tool.command {
        Commands::Encode { data } => println!("encode {data}"),
        Commands::Decode { data } => println!("decode {data}"),
    }
}
