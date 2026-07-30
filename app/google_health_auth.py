# -*- coding: utf-8 -*-
"""
Gestionnaire OAuth2 pour Google Health API v4
Scopes mappés depuis Fitbit Web API → Google Health API
Documentation: https://developers.google.com/health/reference/rest/v4
"""
import json
import os
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
import google.auth.exceptions
import requests

# Scopes mappés depuis Fitbit (voir doc officielle)
SCOPES = [
    "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",   # ← activity, cardio_fitness
    "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",    # ← heartrate, weight, spo2, respiratory_rate, temperature
    "https://www.googleapis.com/auth/googlehealth.sleep.readonly",  # ← sleep
    "https://www.googleapis.com/auth/googlehealth.profile.readonly",    # ← profile
]

class GoogleHealthAuthManager:
    def __init__(self, json_file: str, client_secrets_file: str = "client_secret/client_secret_test_0001.json"):
        """
        Initialise le gestionnaire d'authentification Google Health
        
        :param json_file: Chemin vers le fichier JSON contenant les watches/tokens
        :param client_secrets_file: Chemin vers le fichier client_secret_*.json téléchargé depuis Google Cloud Console
        """
        self.json_file = json_file
        self.client_secrets_file = client_secrets_file
        self.data = self._load_data()
        self.watches = self.data.get("watches", [])
        
    def _load_data(self) -> dict:
        """Charge les données depuis le fichier JSON"""
        try:
            with open(self.json_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"watches": []}
    
    def _save_data(self):
        """Sauvegarde les données dans le fichier JSON"""
        os.makedirs(os.path.dirname(self.json_file) or ".", exist_ok=True)
        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4, ensure_ascii=False)
    
    def start_oauth_flow(self, client_id: str, port: int = 8080) -> dict:
        """Lance le flux OAuth2"""
        
        flow = InstalledAppFlow.from_client_secrets_file(
            self.client_secrets_file,
            scopes=SCOPES,
            # Pas de redirect_uri explicite : la lib gère localhost automatiquement
        )
        
        creds = flow.run_local_server(
            port=port,  # ← Utilise 8080 pour matcher votre config
            prompt="consent",
            authorization_prompt_message="Autorisez l'accès à vos données de santé.",
            success_message="✅ Authentification réussie ! Fermez cet onglet.",
            open_browser=True
        )
        
        return {
            "access_token": creds.token,
            "refresh_token": creds.refresh_token,
            "expires_at": creds.expiry.isoformat() if creds.expiry else None,
            "scopes": creds.scopes,
            "token_type": "Bearer"
        }


    
    def refresh_single_token(self, watch: dict) -> bool:
        """
        Rafraîchit un token d'accès expiré en utilisant le refresh_token
        
        :param watch: Dictionnaire contenant les infos de la montre
        :return: True si le rafraîchissement a réussi, False sinon
        """
        client_id = watch.get("client_id")
        client_secret = watch.get("client_secret")
        token_info = watch.get("token", {})
        
        refresh_token = token_info.get("refresh_token")
        expires_at = token_info.get("expires_at")
        
        # Vérifier si le token est encore valide
        if expires_at:
            try:
                expiry = datetime.fromisoformat(expires_at)
                # Ajouter une marge de 5 minutes pour éviter les problèmes de timing
                if expiry > datetime.now(expiry.tzinfo) + timedelta(minutes=5):
                    return True
            except (ValueError, AttributeError):
                pass
        
        if not refresh_token:
            return False
        
        try:
            # Recréer les credentials avec le refresh_token
            creds = Credentials(
                token=token_info.get("access_token"),
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=client_id,
                client_secret=client_secret,
                scopes=token_info.get("scopes", SCOPES)
            )
            
            # Rafraîchir le token
            creds.refresh(Request())
            
            # Mettre à jour les tokens dans le dictionnaire watch
            watch["token"]["access_token"] = creds.token
            watch["token"]["expires_at"] = creds.expiry.isoformat() if creds.expiry else None
            
            return True
            
        except google.auth.exceptions.RefreshError as e:
            return False
        except Exception as e:
            return False
    
    def refresh_all_tokens(self) -> dict:
        """
        Tente de rafraîchir tous les tokens des watches enregistrées
        
        :return: Dictionnaire avec le statut de chaque watch
        """
        results = {}
        
        for watch in self.watches:
            client_id = watch.get("id", "inconnu")
            success = self.refresh_single_token(watch)
            results[client_id] = {
                "success": success,
                "needs_reauth": not success
            }
            if not success:
                pass
        
        # Sauvegarder les mises à jour
        self._save_data()
        return results
    
    def get_credentials(self, client_id: str) -> Credentials | None:
        """
        Retourne un objet Credentials valide pour un client_id donné
        
        :param client_id: ID de la montre/client
        :return: Objet Credentials ou None si non trouvé/invalide
        """
        watch = next((w for w in self.watches if w["client_id"] == client_id), None)
        
        if not watch:
            return None
        
        token_info = watch.get("token", {})
        
        # Tenter de rafraîchir si nécessaire
        if not self.refresh_single_token(watch):
            return None
        
        # Créer et retourner les credentials
        return Credentials(
            token=token_info["access_token"],
            refresh_token=token_info.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=watch["client_id"],
            client_secret=watch["client_secret"],
            scopes=token_info.get("scopes", SCOPES)
        )

def get_legacy_user_id(access_token: str) -> tuple[str | None, str | None]:
    """
    Appelle GET /v4/users/me/identity et retourne (legacyUserId, healthUserId).
    Retourne (None, None) en cas d'erreur.

    Doc: https://developers.google.com/health/reference/rest/v4/users/getIdentity
    """
    url = "https://health.googleapis.com/v4/users/me/identity"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        body = resp.json()
        legacy_id  = body.get("legacyUserId")
        health_id  = body.get("healthUserId")
        return legacy_id, health_id
    except requests.HTTPError as e:
        return None, None
    except Exception as e:
        return None, None
    
# =============================================================================
# Exemple d'utilisation
# =============================================================================
# if __name__ == "__main__":
#     JSON_FILE = "json_tokens.json"
#     CLIENT_SECRETS = "client_secret_test_0001.json"
    
#     # Initialisation
#     auth_manager = GoogleHealthAuthManager(JSON_FILE, CLIENT_SECRETS)
    
#     # Exemple 1: Nouvelle authentification pour une watch
#     # new_tokens = auth_manager.start_oauth_flow("1075119846255-44cqffq8bki6th2groqm3cmpsg4s5m0k.apps.googleusercontent.com")
#     # print(new_tokens)
    
#     # Exemple 2: Rafraîchir tous les tokens existants
#     results = auth_manager.refresh_all_tokens()
#     print(f"\n Résultats: {results}")
    
#     # Exemple 3: Obtenir des credentials pour un client spécifique
#     creds = auth_manager.get_credentials("1075119846255-44cqffq8bki6th2groqm3cmpsg4s5m0k.apps.googleusercontent.com")