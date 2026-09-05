use std::io::Error;

use arboard::Clipboard;
use crossterm::{cursor::MoveTo, execute, style::{Color, Stylize}, terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen}};

use gestionnaire_core::*;
use gestionnaire_core::utilitaires::*;
use gestionnaire_core::chaine_securisee::*;
use gestionnaire_core::gestionnaire_cle::Session;

enum SelectionMenuPrincipal {
    Rechercher,
    Ajouter,
    Principal,
    Parametres,
    Quitter,
    Entree(usize),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {


    // let mut session = Session::new(gestionnaire_cle::Fournisseur::Ram(gestionnaire_cle::FournisseurRam::new()));
    
    let mut session = Session::new(
       gestionnaire_cle::Fournisseur::Ephemere(gestionnaire_cle::FournisseurEphemere::new())
    );

    let mut stdout = std::io::stdout();
    
    execute!(stdout, EnterAlternateScreen)?;

    let resultat = execution_principale(&mut session);

    execute!(stdout, LeaveAlternateScreen)?;

    if let Err(e) = resultat {
        eprintln!("{}{}", "Erreur : ".dark_red().bold(), e.to_string().red());
        return Ok(());
    }

    Ok(())
}

fn formater_message_entrees(nombre: usize) -> ChaineSecurisee {
    ChaineSecurisee::new(format!(
        "{} mot{} de passe enregistré{}",
        nombre,
        if nombre == 1 { "" } else { "s" },
        if nombre == 1 { "" } else { "s" }
    ))
}

fn construire_options_menu_principal(entrees: &[(usize, ChaineSecurisee)]) -> Vec<(ChaineSecurisee, ChaineSecurisee, ChaineSecurisee)> {
    
    let mut options: Vec<(ChaineSecurisee, ChaineSecurisee, ChaineSecurisee)> = entrees
        .iter()
        .map(|(i, e)| (
            ChaineSecurisee::new(format!("entry:{}", i)),
            e.clone(),
            ChaineSecurisee::new(String::new())
        ))
        .collect(); 

    let menus = vec![
        ("rechercher", "⌕ Rechercher..."),
        ("ajouter", "+ Ajouter une nouvelle entrée"),
        ("principal", "⚷ Mot de passe principal"),
        ("parametres", "⚙ Paramètres"),
        ("quitter", "← Quitter"),
    ];

    for (cle, label) in menus {
        options.push((
            ChaineSecurisee::new(cle.to_string()),
            ChaineSecurisee::new(label.to_string()),
            ChaineSecurisee::new(String::new())
        ));
    }

    options
}

fn parser_selection_menu_principal(choix: &ChaineSecurisee) -> SelectionMenuPrincipal {
    
    choix.expose(|choix_string| {

        match choix_string.as_str() {
            "rechercher" => SelectionMenuPrincipal::Rechercher,
            "ajouter" => SelectionMenuPrincipal::Ajouter,
            "principal" => SelectionMenuPrincipal::Principal,
            "parametres" => SelectionMenuPrincipal::Parametres,
            "quitter" => SelectionMenuPrincipal::Quitter,
            valeur if valeur.starts_with("entry:") => {
                let index = valeur[6..].parse::<usize>().unwrap_or(usize::MAX);
                SelectionMenuPrincipal::Entree(index)
            }
            _ => SelectionMenuPrincipal::Quitter,
        }
    })
}

fn nettoyer_ecran() {

    let mut stdout = std::io::stdout();
    let _ = execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
}

fn execution_principale(session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    
    nettoyer_ecran();
    cliclack::intro("Gestionnaire de mot de passe".cyan().bold())?;

    let mut coloriser_types_caracteres = true;
    let mut essais_par_seconde = 1e10;

    let mut mdps = if mdps_existent() {
        boucle_authentification_fichier(session)?
    } else {
        initialiser_nouveau_coffre(session)?
    };

    // Menu principal
    loop {

        nettoyer_ecran();
        cliclack::intro("Menu Principal".cyan().bold())?;

        let mdp = boucle_authentification()?;

        let mut noms: Vec<(usize, ChaineSecurisee)> = noms_mdps(&mdps, Some(&mdp), session)?
            .into_iter()
            .enumerate()
            .map(|(i, nom)| (i, nom))
            .collect();

        noms.sort_by(|a, b| {
            a.1.expose(|a_string| {
                a_string
                    .to_lowercase()
                    .cmp(&b.1.expose(|b_string| b_string.to_lowercase()))
            })
        });

        let options = construire_options_menu_principal(&noms);
        let items: Vec<(&ChaineSecurisee, ChaineAfficheable<'_>, ChaineAfficheable<'_>)> = options
            .iter()
            .map(|(cle, label_secu, texte)| {
                (
                    cle,
                    label_secu.to_ui(),
                    texte.to_ui(),
                )
            })
            .collect();

        let message_secu = formater_message_entrees(noms.len());

        let choix = cliclack::select(message_secu.to_ui())
        .items(&items)
        .interact()?;
        
        match parser_selection_menu_principal(&choix) {

            SelectionMenuPrincipal::Rechercher => {
                menu_recherche(noms, &mut mdps, coloriser_types_caracteres, essais_par_seconde, session)?;
            },
            SelectionMenuPrincipal::Principal => {
                menu_mot_de_passe_principal(&mut mdps, coloriser_types_caracteres, essais_par_seconde, session)?;
            },
            SelectionMenuPrincipal::Ajouter => {
                menu_ajouter_entree(&mut mdps, session)?;
            },
            SelectionMenuPrincipal::Parametres => {
                menu_parametres(&mut mdps, &mut coloriser_types_caracteres, &mut essais_par_seconde, session)?;
            },
            SelectionMenuPrincipal::Entree(index) => {
                menu_details_entree(&mut mdps, index, coloriser_types_caracteres, essais_par_seconde, session)?;
            },
            SelectionMenuPrincipal::Quitter => break,
        }
    }

    Ok(())
}

fn initialiser_nouveau_coffre(session: &mut Session) -> Result<FichierMDP, Box<dyn std::error::Error>> {

    cliclack::log::info("Aucun gestionnaire trouvé, Nouvelle configuration")?;

    let mdp_principal = loop {

        let mdp1: ChaineSecurisee = ChaineSecurisee::new(
            cliclack::password("Choisissez un mot de passe principal :".bold())
                .mask('•')
                .interact()?
        );

        let mdp2: ChaineSecurisee = ChaineSecurisee::new(
            cliclack::password("Confirmez le nouveau mot de passe :")
                .mask('•')
                .interact()?
        );

        if mdp1.est_vide() {
            continue;
        }

        if mdp1 == mdp2 {
            break mdp1;
        }

        cliclack::log::warning("Les mots de passe ne correspondent pas.")?;
    };

    Ok(nouveaux_mdps(mdp_principal, session)?)
}

fn boucle_authentification_fichier(session: &mut Session) -> Result<FichierMDP, Box<dyn std::error::Error>> {

    loop {
        let mdp_input = ChaineSecurisee::new(cliclack::password("Saississez votre mot de passe principal :")
            .mask('•')
            .interact()?);
        
        let resultat_verification = verifier_mdp_principal_fichier(&mdp_input, session)?;

        match resultat_verification {
            Some(fichier) => return Ok(fichier),
            None => {
                nettoyer_ecran();
                cliclack::intro(format!("{}, {}", if resultat_verification.is_some() { "" } else { "Mot de passe incorrect" }.red().bold(), "Authentification".cyan().bold()))?;
            }
        }
    }
}

fn boucle_authentification() -> Result<ChaineSecurisee, ErreurGestionnaire> {

    loop {
        
        let mdp_input = ChaineSecurisee::new(cliclack::password("Mode éphémère : Saississez votre mot de passe principal :")
            .mask('•')
            .interact().map_err(|_| ErreurGestionnaire::ErreurSaisie("Mot de passe principal".to_string()))?);

        if verifier_mdp_principal(&mdp_input)? {
            return Ok(mdp_input);
        }
    }
}


fn construire_options_recherche(resultats: &[(usize, ChaineSecurisee)]) -> Vec<(ChaineSecurisee, ChaineSecurisee, ChaineSecurisee)> {
    resultats
        .iter()
        .map(|(i, e)| (ChaineSecurisee::new(format!("entry:{}", i)), e.clone(), ChaineSecurisee::new(String::new())))
        .collect()
}

fn menu_recherche(entrees: Vec<(usize, ChaineSecurisee)>, fichier: &mut FichierMDP, coloriser_types_caracteres: bool, essais_par_seconde: f64, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {

    let recherche: ChaineSecurisee = ChaineSecurisee::new(
        cliclack::input("Rechercher un mot de passe :".cyan().bold())
        .placeholder("ex: mail")
        .interact()?
    );

    let filtre = recherche.expose(|recherche_string| recherche_string.to_lowercase());
    let resultats: Vec<(usize, ChaineSecurisee)> = entrees.into_iter()
        .filter(|(_, e)| e .expose(|e_string| e_string.to_lowercase().contains(&filtre)))
        .collect();

    if resultats.is_empty() {
        cliclack::log::warning("Aucun service ne correspond à votre recherche.".yellow().bold())?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        return Ok(());
    }

    let options = construire_options_recherche(&resultats);
    let choix = &cliclack::select(format!("{} résultat{} trouvé{}", resultats.len(), if resultats.len() == 1 { "" } else { "s" }, if resultats.len() == 1 { "" } else { "s" }))
    .items(&options.iter()
    .map(|(cle, label, texte)| (cle, label.to_ui(), texte.to_ui())).collect::<Vec<(&ChaineSecurisee, ChaineAfficheable<'_>, ChaineAfficheable<'_>)>>())
    .interact()?;

    if let Some(index) = choix.expose(|c| c.strip_prefix("entry:").and_then(|s| s.parse::<usize>().ok())) {
        if let Some((_, _)) = resultats.into_iter().find(|(i, _)| *i == index) {
            menu_details_entree(fichier, index, coloriser_types_caracteres, essais_par_seconde, session)?;
        }
    }

    Ok(())
}

fn menu_details_entree(fichier: &mut FichierMDP, index: usize, coloriser_types_caracteres: bool, essais_par_seconde: f64, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    
    let mdp = boucle_authentification()?;

    let entree = recuperer_champ_informations(fichier, index, Some(&mdp), session)?;
    let mut visibilite_mdps = vec![false; entree.mdps.len()];
    let mut complexite_mdps = vec![false; entree.mdps.len()];

    'actions: loop {
        
        nettoyer_ecran();
        
        entree.nom.expose(|nom_string| cliclack::log::info(format!("{:<19} : {}","Nom".bold(), nom_string.clone().cyan())))?;
        
        for (i, id) in entree.identifiants.iter().enumerate() {
            cliclack::log::info(format!("{:<19} : {}", format!("{} {}", "Identifiant".bold(), (i + 1).to_string().bold()), id.to_ui()))?;
        }
        
        let mut options = Vec::new();

        for (i, mdp) in entree.mdps.iter().enumerate() {

            if let Some(visible) = visibilite_mdps.get(i) {
                if let Some(complexite) = complexite_mdps.get(i) {

                    let chaine_mdp = if *visible {
                        if coloriser_types_caracteres {
                            coloriser_mot_de_passe(mdp.clone())
                        } else {
                            ChaineSecurisee::new(mdp.expose(|s| s.clone().cyan().to_string()))
                        }
                    } else {
                        ChaineSecurisee::new(mdp.expose(|s| { "•".repeat(s.chars().count()).dark_grey().to_string()}))  
                    };

                    let (score, entropie, tentatives, temps) = informations_formattees_securite_mdp(&mdp.clone(), essais_par_seconde);

                    let force = match score {
                        NiveauSecurite::TresFaible => "très faible".dark_red(),
                        NiveauSecurite::Faible => "faible".red(),
                        NiveauSecurite::Modere => "modérée".yellow(),
                        NiveauSecurite::Fort => "fort".green(),
                        NiveauSecurite::TresFort => "très fort".dark_green(),
                        NiveauSecurite::ExtremementFort => "extrêmement fort".dark_green(),
                    };

                    cliclack::log::info(format!("{:<19} : {}\n", format!("{} {}", "Mot de passe".bold(), (i + 1).to_string().bold()), chaine_mdp.expose(|s| s.clone())))?;

                    if *complexite {
                        cliclack::log::info(
                            format!("{:<19} : {:.2} bits ({force})\n{:<19} : {temps} ({essais_par_seconde:.0e} essais/seconde)\n{:<19} : {tentatives}",
                            "Entropie".bold(), entropie,
                            "Durée de protection".bold(),
                            "Tentatives estimées".bold()))?;
                    }

                    let label_visibilite = if *visible { "Cacher" } else { "Afficher" }.to_string();
                    let label_complexite = if *complexite { 
                        String::from("⛨ Cacher les informations\n")
                    } else {
                        format!("⛨ Plus d'informations : {} ({force})\n", entropie.round() as usize)
                    };

                    options.push((ChaineSecurisee::new(format!("visibilite_{}", i)), ChaineSecurisee::new(format!("Mot de passe {} : {}", i + 1,label_visibilite.clone())), ChaineSecurisee::new(String::new())));
                    options.push((ChaineSecurisee::new(format!("copier_{}", i)), ChaineSecurisee::new(String::from("⎘ Copier")), ChaineSecurisee::new(String::new())));
                    options.push((ChaineSecurisee::new(format!("complexite_{}", i)), ChaineSecurisee::new(label_complexite), ChaineSecurisee::new(String::new())));

                }
            }
        }

        entree.commentaire.expose(|c| -> Result<(), Box<dyn std::error::Error>> {
            if !c.is_empty() {
                cliclack::log::info(format!("{:<19} : {}", "Commentaire".bold(), c.clone().cyan()))?;
            }
            Ok(())
        })?;
        

        options.push((ChaineSecurisee::from_str("vider"), ChaineSecurisee::from_str("⌫ Vider le presse-papier"), ChaineSecurisee::new(String::new())));
        options.push((ChaineSecurisee::from_str("modifier"), ChaineSecurisee::from_str("✎ Modifier"), ChaineSecurisee::new(String::new())));
        options.push((ChaineSecurisee::from_str("supprimer"), ChaineSecurisee::from_str("✕ Supprimer"), ChaineSecurisee::new(String::new())));
        options.push((ChaineSecurisee::from_str("retour"), ChaineSecurisee::from_str("↩ Retour"), ChaineSecurisee::new(String::new())));
        
        let items = options.iter().map(|(cle, label, texte)| 
            (cle.expose(| c| c.clone()), label.to_ui(), texte.to_ui())).collect::<Vec<(String, ChaineAfficheable<'_>, ChaineAfficheable<'_>)>>();

        let choix = cliclack::select("")
            .items(&items)
            .interact()?;

        
        if let Some(suffix) = choix.strip_prefix("visibilite_") {
            let i = suffix.parse::<usize>().unwrap_or(0);
            if i < visibilite_mdps.len() {

                if let Some(visible) = visibilite_mdps.get_mut(i) {
                    *visible = !*visible;
                }
            }
            continue 'actions;
        }

        if let Some(suffix) = choix.strip_prefix("copier_") {
            let i = suffix.parse::<usize>().unwrap_or(0);
            
            copier_presse_papier(i, &entree);

            continue 'actions;
        }

        if let Some(suffix) = choix.strip_prefix("complexite_") {
            let i = suffix.parse::<usize>().unwrap_or(0);
            
            if i < complexite_mdps.len() {

                if let Some(complexite) = complexite_mdps.get_mut(i) {
                    *complexite = !*complexite;
                }
            }

            continue 'actions;
        }

        match choix.as_str() {
            "vider" => {
                vider_presse_papier()?;
            }
            "modifier" => {
                menu_modifier_specifique(fichier, index, entree, session)?;
                break 'actions;
            }
            "supprimer" => {
                nettoyer_ecran();
                let confirmer = cliclack::confirm("Êtes-vous sûr de vouloir supprimer définitivement ce mot de passe ?".red().bold())
                    .initial_value(false)
                    .interact()?;

                if confirmer {
                    supprimer_entree(fichier, index)?;

                    let mdp = boucle_authentification()?;

                    sauvegarder_mdps(fichier, Some(&mdp),session)?;
                    break 'actions;
                }
            }
            _ => break 'actions,
        }
        
    }
    Ok(())
}

fn vider_presse_papier() -> Result<(), Box<dyn std::error::Error>> {

    let mut cb = Clipboard::new()?;
    cb.clear()?;
    Ok(())
}

fn copier_presse_papier(indice_mdp: usize, entree: &ChampInformations) {

    if let Ok(mut cb) = Clipboard::new() {
        if let Some(mdp) = entree.mdps.get(indice_mdp) {
            
            let _ = cb.set_text(mdp.expose(|mdp_string| mdp_string.clone()));
        }
    }
}

fn generer_mot_de_passe_aleatoire() -> Result<ChaineSecurisee, Box<dyn std::error::Error>> {
    
    let longueur = loop {
        let valeur = ChaineSecurisee::new(
            cliclack::input("Taille du mot de passe :")
                .placeholder("1-256")
                .default_input("16")
                .interact()?
        );

        let parsed = valeur.expose(|s| s.trim().parse::<usize>());
        match parsed {
            Ok(n) if (1..=256).contains(&n) => break n,
            _ => {
                cliclack::log::warning("Veuillez entrer un nombre entre 1 et 256.")?;
            }
        }
    };

    let (minuscules, majuscules, chiffres, speciaux) = loop {
        let minuscules = cliclack::confirm("Inclure des minuscules ?").initial_value(true).interact()?;
        let majuscules = cliclack::confirm("Inclure des majuscules ?").initial_value(true).interact()?;
        let chiffres = cliclack::confirm("Inclure des chiffres ?").initial_value(true).interact()?;
        let speciaux = cliclack::confirm("Inclure des caractères spéciaux ?").initial_value(true).interact()?;

        if minuscules || majuscules || chiffres || speciaux {
            break (minuscules, majuscules, chiffres, speciaux);
        }

        cliclack::log::warning("Sélectionnez au moins une catégorie de caractères.")?;
    };

    let mot_de_passe = generer_mdp_aleatoire(longueur, minuscules, majuscules, chiffres, speciaux)?;
    Ok(mot_de_passe)
}

fn demander_mot_de_passe() -> Result<ChaineSecurisee, Box<dyn std::error::Error>> {
    let options = vec![
        (ChaineSecurisee::new("manuel".to_string()), ChaineSecurisee::new("⌨ Saisir un mot de passe manuel".to_string()), ChaineSecurisee::new(String::new())),
        (ChaineSecurisee::new("generer".to_string()), ChaineSecurisee::new("⚄ Générer un mot de passe".to_string()), ChaineSecurisee::new(String::new())),
    ];

    let items: Vec<(&ChaineSecurisee, ChaineAfficheable<'_>, ChaineAfficheable<'_>)> = options
        .iter()
        .map(|(cle, label, texte)| (cle, label.to_ui(), texte.to_ui()))
        .collect();

    let choix = cliclack::select("Choisissez un mot de passe :")
        .items(&items)
        .interact()?;

    choix.expose(|choix_string| {
    
        match choix_string.as_str() {
            "manuel" => cliclack::password("Mot de passe :")
                .mask('•')
                .interact()
                .map(|s| ChaineSecurisee::new(s))
                .map_err(Into::into),
            _ => generer_mot_de_passe_aleatoire(),
        }
    })
}

fn saisir_entree() -> Result<ChampInformations, Box<dyn std::error::Error>> {
    nettoyer_ecran();
    cliclack::intro("Ajouter une entrée".bold())?;

    let nom = ChaineSecurisee::new(cliclack::input("Nom            :").interact()?);
    let mut identifiants = Vec::new();
    let mut mots_de_passe = Vec::new();

    loop {
        identifiants.push(ChaineSecurisee::new(cliclack::input("Identifiant    :").interact()?));

        let ajouter_autre = cliclack::confirm("Ajouter un autre identifiant ?")
            .initial_value(false)
            .interact()?;

        if !ajouter_autre {
            break;
        }
    }

    loop {
        mots_de_passe.push(demander_mot_de_passe()?);

        let ajouter_autre = cliclack::confirm("Ajouter un autre mot de passe ?")
            .initial_value(false)
            .interact()?;

        if !ajouter_autre {
            break;
        }
    }

    let commentaire = ChaineSecurisee::new( cliclack::input("Commentaire    :")
        .required(false)
        .interact()?
    );

    Ok(ChampInformations {
        nom: nom,
        identifiants: identifiants,
        mdps: mots_de_passe,
        commentaire: commentaire,
    })
}

fn saisir_entree_modifie(entree: &ChampInformations) -> Result<ChampInformations, Box<dyn std::error::Error>> {
    nettoyer_ecran();
    
    let nom_actuel = entree.nom.expose(|s| s.clone());
    let com_actuel = entree.commentaire.expose(|s| s.clone());

    let nom = ChaineSecurisee::new(cliclack::input("Nouveau nom :")
        .default_input(&nom_actuel)
        .interact()?
    );

    let mut identifiants = Vec::new();
    let mut i = 0;

    loop {
        let id_actuel = entree.identifiants.get(i).map(|id| id.expose(|s| s.clone())).unwrap_or_default();
        
        identifiants.push(ChaineSecurisee::new(
            cliclack::input("Nouvel Identifiant :")
                .default_input(&id_actuel)
                .interact()?
        ));

        let ajouter_autre = cliclack::confirm("Ajouter un autre identifiant ?")
            .initial_value(false)
            .interact()?;

        if !ajouter_autre {
            break;
        }

        i += 1;
    }

    i = 0;
    let mut mots_de_passe = Vec::new(); 

    loop {
        match &entree.mdps.get(i) {
            Some(mdp_actuel) => {
        
                let modif_mdp = cliclack::confirm("Modifier le mot de passe ?")
                    .initial_value(false)
                    .interact()?;
                
                mots_de_passe.push(if modif_mdp { demander_mot_de_passe()? } else { (*mdp_actuel).clone() });

            },
            None => {

                let modif_mdp = cliclack::confirm("Ajouter un nouveau mot de passe ?")
                    .initial_value(false)
                    .interact()?;

                if modif_mdp {
                    mots_de_passe.push(demander_mot_de_passe()?);
                } else {
                    break;
                }

            }
        }

        i += 1;
    }

    let commentaire = ChaineSecurisee::new(cliclack::input("Nouveau commentaire :")
        .default_input(&com_actuel)
        .interact()?
    );

    Ok(ChampInformations {
        nom,
        identifiants,
        mdps: mots_de_passe,
        commentaire,
    })
}

fn coloriser_mot_de_passe(mdp: ChaineSecurisee) -> ChaineSecurisee {
    
    ChaineSecurisee::new(mdp.expose(|string_mdp| {
        
        string_mdp.chars().map(|ch| {
        
            if ch.is_ascii_lowercase() {
                ch.to_string().with(Color::Rgb { r: 100, g: 200, b: 255 }).to_string()
            } else if ch.is_ascii_uppercase() {
                ch.to_string().with(Color::Rgb { r: 255, g: 120, b: 120 }).to_string()
            } else if ch.is_ascii_digit() {
                ch.to_string().with(Color::Rgb { r: 120, g: 255, b: 120 }).to_string()
            } else {
                ch.to_string().with(Color::Rgb { r: 255, g: 200, b: 100 }).to_string()
            }
        }).collect::<String>() 
    }))
}

fn demander_nombre_essais(essais_par_seconde: &mut f64) -> Result<(), Box<dyn std::error::Error>> {

    let valeur_str: String = cliclack::input("Essais par seconde utilisés dans le calcul de durée de protection des mots de passe")
        .placeholder(&essais_par_seconde.to_string())
        .validate(|input: &String| {

            match input.parse::<f64>() {
                Ok(val) if val > 0.0 && val < 1e15 => Ok(()),
                Ok(_) => Err("Le nombre doit être comprise entre 0 et 1e15"),
                Err(_) => Err("Veuillez entrer un nombre ou une notation scientifique valide"),
            }
        })
        .interact()?;
    
    
    if let Some(nombre) = valeur_str.parse().ok() {

        *essais_par_seconde = nombre;
        return Ok(());
    }
    
    Err(Box::new(Error::new(std::io::ErrorKind::InvalidInput, "Veuillez entrer un nombre ou une notation scientifique valide")))
}



fn menu_ajouter_entree(fichier: &mut FichierMDP, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {

    let nouvelle_entree = saisir_entree()?;
    let mdp = boucle_authentification()?;

    ajouter_champ_informations(fichier, nouvelle_entree, Some(&mdp), session)?;
    
    Ok(())
}

fn menu_modifier_specifique(fichier: &mut FichierMDP, index: usize, entree: ChampInformations, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    
    let nouveau_champ_informations = saisir_entree_modifie(&entree)?;
    let mdp = boucle_authentification()?;

    Ok(modifier_champ_informations(fichier, index, nouveau_champ_informations, Some(&mdp), session)?)
}

fn menu_modifier_mot_de_passe_principal(fichier: &mut FichierMDP, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {

    nettoyer_ecran();
    cliclack::intro("Changer le mot de passe principal".cyan().bold())?;

    let nouveau_mdp = loop {
        let mdp1 = ChaineSecurisee::new(cliclack::password("Nouveau mot de passe principal :")
            .mask('•')
            .interact()?
        );
        let mdp2 = ChaineSecurisee::new(cliclack::password("Confirmez le nouveau mot de passe :")
            .mask('•')
            .interact()?
        );

        if mdp1.est_vide() {
            continue;
        }

        if mdp1 == mdp2 {
            break mdp1;
        }

        cliclack::log::warning("Les mots de passe ne correspondent pas.")?;
    };

    let mdp = boucle_authentification()?;
    modifier_mdp_principal(fichier, nouveau_mdp, Some(&mdp), session)?;
    Ok(())
}

fn menu_mot_de_passe_principal(fichier: &mut FichierMDP, coloriser_types_caracteres: bool, essais_par_seconde: f64, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    
    let mut mdp_visible = false;
    let mut mdp_complexite = false;

    loop {
        nettoyer_ecran();

        cliclack::intro("Mot de passe principal".cyan().bold())?;

        let mdp = boucle_authentification()?;

        let mdp_principal_dechiffre = recuperer_mdp_principal(fichier, Some(&mdp),session)?;

        let chaine_mdp = if mdp_visible {
            if coloriser_types_caracteres {
                coloriser_mot_de_passe(mdp_principal_dechiffre.clone())
            } else {
                ChaineSecurisee::new(mdp_principal_dechiffre.expose(|s| s.clone().cyan().to_string()))
            }
        } else {
            ChaineSecurisee::new(mdp_principal_dechiffre.expose(|s| { "•".repeat(s.chars().count()).dark_grey().to_string()}))  
        };
        

        let (score, entropie, tentatives, temps) = informations_formattees_securite_mdp(&mdp_principal_dechiffre, essais_par_seconde);

        let force = match score {
            NiveauSecurite::TresFaible => "très faible".dark_red(),
            NiveauSecurite::Faible => "faible".red(),
            NiveauSecurite::Modere => "modérée".yellow(),
            NiveauSecurite::Fort => "fort".green(),
            NiveauSecurite::TresFort => "très fort".dark_green(),
            NiveauSecurite::ExtremementFort => "extrêmement fort".dark_green(),
        };

        cliclack::log::info(format!("{:<19} : {}\n", "Mot de passe".bold(), chaine_mdp.expose(|s| s.clone())))?;

        let label_visibilite = if mdp_visible { "Cacher" } else { "Afficher" }.to_string();
        let label_complexite = if mdp_complexite { 
            String::from("⛨ Cacher les informations\n")
        } else {
            format!("⛨ Plus d'informations : {} ({force})\n", entropie.round() as usize)
        };

        let options: Vec<(ChaineSecurisee, ChaineSecurisee, ChaineSecurisee)> = vec![
            (ChaineSecurisee::new("visibilite".to_string()), ChaineSecurisee::new(label_visibilite), ChaineSecurisee::new(String::new())),
            (ChaineSecurisee::new("modifier".to_string()), ChaineSecurisee::new("✎ Modifier".to_string()), ChaineSecurisee::new(String::new())),
            (ChaineSecurisee::new("complexite".to_string()), ChaineSecurisee::new(label_complexite), ChaineSecurisee::new(String::new())),
            (ChaineSecurisee::new("retour".to_string()), ChaineSecurisee::new("↩ Retour".to_string()), ChaineSecurisee::new(String::new())),
        ];

        if mdp_complexite {
            cliclack::log::info(
                format!("{:<19} : {:.2} bits ({force})\n{:<19} : {temps} ({essais_par_seconde:.0e} essais/seconde)\n{:<19} : {tentatives}",
                "Entropie".bold(), entropie,
                "Durée de protection".bold(),
                "Tentatives estimées".bold()))?;
        }


        let items: Vec<(String, ChaineAfficheable<'_>, ChaineAfficheable<'_>)> = options
            .iter()
            .map(|(cle, label, texte)| (cle.expose(|c| c.clone()), label.to_ui(), texte.to_ui()))
            .collect();

        let choix = cliclack::select("")
            .items(&items)
            .interact()?;

        match choix.as_str() {
            "modifier" => {
                menu_modifier_mot_de_passe_principal(fichier, session)?;
                break;
            },
            "visibilite" => {
                mdp_visible = !mdp_visible;
                continue;
            },
            "complexite" => {
                mdp_complexite = !mdp_complexite;
                continue;
            },
            _ => break,
        }
    }
    Ok(())
}

fn menu_parametres(mdps: &mut FichierMDP, coloriser_types_caracteres: &mut bool, essais_par_seconde: &mut f64, session: &mut Session) -> Result<(), Box<dyn std::error::Error>> {
    
    loop {
        nettoyer_ecran();

        let coloriser = format!("✎ {} les caractères des mots de passe par type" ,if *coloriser_types_caracteres { "Coloriser" } else { "Ne pas coloriser" });

        let options: Vec<(String, String, String)> = vec![
            ("coloriser".to_string(), coloriser, String::new()),
            ("essais".to_string(), "⚙ Modifier le nombre d'essais par seconde".to_string(), String::new()),
            ("sauvegarder".to_string(), "⤓ Sauvegarder les mots de passe".to_string(), String::new()),
            ("supprimer".to_string(), "✕ Réinitialiser le gestionnaire".to_string(), String::new()),
            ("retour".to_string(), "↩ Retour".to_string(), String::new()),
        ];

        let choix = cliclack::select("")
            .items(&options)
            .interact()?;

        match choix.as_str() {

            "coloriser" => {
                *coloriser_types_caracteres = !*coloriser_types_caracteres;
                continue;
            },
            "essais" => {
                
                nettoyer_ecran();
                demander_nombre_essais(essais_par_seconde)?;
            }
            "sauvegarder" => {
                creer_sauvegarde()?;
                continue;
            },
            "supprimer" => {
                
                nettoyer_ecran();
                let confirmer = cliclack::confirm("Êtes-vous sûr de vouloir supprimer définitivement le coffre-fort ?".red().bold())
                    .initial_value(false)
                    .interact()?;
                
                if confirmer {

                    effacer_mdps()?;
                    break;
                }
                continue;
            },
            _ => break,
        }
    }
    
    Ok(())
}