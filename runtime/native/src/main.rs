#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::main() {
        eprintln!("cleo-supervisor: {error:#}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("cleo-supervisor requires Linux; containment is unavailable on this OS");
        std::process::exit(1);
    }
}
