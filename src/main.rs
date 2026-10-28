#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use rand::{distributions::Alphanumeric, Rng};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const OPENSSL_PATH: &str = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe";

#[derive(Default)]
struct CertApp {
    pfx_path: Option<PathBuf>,
    password: String,

    status_history: Vec<String>,

    generated_passphrase: String,
    pending_overwrite: bool,
}

impl CertApp {
    fn add_status(&mut self, message: impl Into<String>) {
        self.status_history.push(message.into());
    }

    fn generate_passphrase() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    fn output_paths(pfx: &Path) -> Result<(PathBuf, PathBuf, PathBuf), String> {
        let stem = pfx
            .file_stem()
            .ok_or("Nom de fichier PFX invalide")?
            .to_string_lossy();

        let dir = pfx
            .parent()
            .ok_or("Impossible de trouver le dossier du PFX")?;

        let out_dir = dir.join(format!("{stem}_extracted"));

        let crt = out_dir.join(format!("{stem}.crt"));
        let key = out_dir.join(format!("{stem}.key"));
        let nopass = out_dir.join(format!("{stem}-nopass.key"));

        Ok((crt, key, nopass))
    }

    fn run_openssl(args: &[&str]) -> Result<(), String> {
        let output = Command::new(OPENSSL_PATH)
            .args(args)
            .output()
            .map_err(|e| format!("Erreur lancement OpenSSL: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(stderr.to_string());
        }

        Ok(())
    }

    fn process_certificate(&mut self, force_overwrite: bool) {
        let Some(pfx_path) = &self.pfx_path else {
            self.add_status("Dépose d’abord un fichier .pfx ou .p12.");
            return;
        };

        if !Path::new(OPENSSL_PATH).exists() {
            self.add_status(format!("OpenSSL introuvable:\n{OPENSSL_PATH}"));
            return;
        }

        if self.password.trim().is_empty() {
            self.add_status("Entre le mot de passe du PFX.");
            return;
        }

        let pfx = pfx_path.to_string_lossy().to_string();

        let (crt_path, key_path, nopass_key_path) = match Self::output_paths(pfx_path) {
            Ok(paths) => paths,
            Err(e) => {
                self.add_status(e);
                return;
            }
        };

        let out_dir = match crt_path.parent() {
            Some(dir) => dir,
            None => {
                self.add_status("Impossible de déterminer le dossier de sortie.");
                return;
            }
        };

        if !out_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(out_dir) {
                self.add_status(format!("Impossible de créer le dossier de sortie:\n{e}"));
                return;
            }
        }

        if !force_overwrite
            && (crt_path.exists() || key_path.exists() || nopass_key_path.exists())
        {
            self.add_status(format!(
                "Des fichiers existent déjà dans:\n{}\n\nClique sur Écraser pour remplacer les fichiers.",
                out_dir.display()
            ));
            self.pending_overwrite = true;
            return;
        }

        self.pending_overwrite = false;

        let crt = crt_path.to_string_lossy().to_string();
        let key = key_path.to_string_lossy().to_string();
        let nopass = nopass_key_path.to_string_lossy().to_string();

        let pfx_password = self.password.clone();
        let random_passphrase = Self::generate_passphrase();

        self.generated_passphrase = random_passphrase.clone();

        self.add_status("Extraction du certificat serveur...");

        let result = (|| -> Result<(), String> {
            Self::run_openssl(&[
                "pkcs12",
                "-in",
                &pfx,
                "-clcerts",
                "-nokeys",
                "-out",
                &crt,
                "-passin",
                &format!("pass:{pfx_password}"),
            ])?;

            Self::run_openssl(&[
                "pkcs12",
                "-in",
                &pfx,
                "-nocerts",
                "-out",
                &key,
                "-passin",
                &format!("pass:{pfx_password}"),
                "-passout",
                &format!("pass:{random_passphrase}"),
            ])?;

            Self::run_openssl(&[
                "rsa",
                "-in",
                &key,
                "-out",
                &nopass,
                "-passin",
                &format!("pass:{random_passphrase}"),
            ])?;

            Ok(())
        })();

        match result {
            Ok(_) => {
                self.add_status(format!(
                    "Terminé.\n\nDossier de sortie:\n{}\n\nCertificat:\n{}\n\nClé avec passphrase:\n{}\n\nClé sans passphrase:\n{}",
                    out_dir.display(),
                    crt_path.display(),
                    key_path.display(),
                    nopass_key_path.display()
                ));
            }
            Err(e) => {
                self.add_status(format!("Erreur OpenSSL:\n{e}"));
            }
        }
    }
}

impl eframe::App for CertApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());

        for file in dropped_files {
            if let Some(path) = file.path {
                let ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default();

                if ext == "pfx" || ext == "p12" {
                    self.pfx_path = Some(path);
                    self.status_history.clear();
                    self.pending_overwrite = false;
                    self.generated_passphrase.clear();
                } else {
                    self.add_status("Fichier non supporté. Utilise un .pfx ou .p12.");
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.heading("PFX Extractor");
                ui.label("Extraction de certificat et de clé privée");
                ui.add_space(8.0);

                ui.label("Fichier PFX / P12");
                let width = ui.available_width();
                let height = (ui.available_height() * 0.22).clamp(100.0, 200.0);
                egui::Frame::group(ui.style()).inner_margin(12.0).show(ui, |ui| {
                    ui.set_min_size(egui::vec2((width - 26.0).max(0.0), height));
                    ui.vertical_centered(|ui| {
                        ui.add_space((height * 0.25).max(8.0));
                        if let Some(path) = &self.pfx_path {
                            ui.label("Fichier sélectionné :");
                            ui.label(path.display().to_string());
                        } else {
                            ui.label("Glisse et dépose ton fichier .pfx ou .p12 ici");
                        }
                    });
                });
                ui.add_space(10.0);
                ui.label("Mot de passe du PFX");
                ui.add_sized([ui.available_width(), 28.0], egui::TextEdit::singleline(&mut self.password)
                    .password(true).hint_text("Mot de passe"));
                ui.add_space(10.0);

                if self.pending_overwrite {
                    ui.colored_label(egui::Color32::YELLOW, "Attention : des fichiers existent déjà.");
                    ui.horizontal(|ui| {
                        if ui.button("Écraser").clicked() { self.process_certificate(true); }
                        if ui.button("Annuler").clicked() {
                            self.pending_overwrite = false;
                            self.add_status("Opération annulée.");
                        }
                    });
                } else if ui.add_sized([ui.available_width(), 32.0], egui::Button::new("Extraire le certificat et la clé privée")).clicked() {
                    self.process_certificate(false);
                }

                if !self.generated_passphrase.is_empty() {
                    ui.add_space(10.0);
                    ui.label("Passphrase générée pour la clé chiffrée");
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 80.0).max(50.0);
                        ui.add(egui::TextEdit::singleline(&mut self.generated_passphrase).desired_width(width).interactive(false));
                        if ui.button("Copier").clicked() { ui.ctx().copy_text(self.generated_passphrase.clone()); }
                    });
                }
                ui.add_space(10.0);
                ui.separator();
                if !Path::new(OPENSSL_PATH).exists() {
                    ui.colored_label(egui::Color32::RED, format!("OpenSSL introuvable : {OPENSSL_PATH}"));
                } else {
                    ui.label(format!("OpenSSL OK : {OPENSSL_PATH}"));
                }
                ui.add_space(8.0);
                ui.label("Historique :");
                let history_height = ui.available_height().max(100.0);
                egui::ScrollArea::vertical().id_salt("history").stick_to_bottom(true)
                    .auto_shrink([false, false]).max_height(history_height).show(ui, |ui| {
                        for entry in &self.status_history {
                            ui.group(|ui| { ui.set_min_width(ui.available_width()); ui.label(entry); });
                            ui.add_space(6.0);
                        }
                    });
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PFX Extractor")
            .with_inner_size([650.0, 650.0])
            .with_min_inner_size([420.0, 450.0])
            .with_resizable(true),
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "PFX Extractor",
        options,
        Box::new(|_cc| Ok(Box::<CertApp>::default())),
    )
}