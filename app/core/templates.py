from fastapi.templating import Jinja2Templates
from pathlib import Path
from app.i18n import t as translate_func
import jinja2

TEMPLATES_DIR = Path(__file__).parents[1] / "templates"

# Ensure the templates directory exists
if not TEMPLATES_DIR.exists():
    raise FileNotFoundError(f"Templates directory not found: {TEMPLATES_DIR}")

# Initialize templates ONLY ONCE
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# CUSTOM FILTERS
def format_datetime(value, format="%d/%m/%Y %H:%M"):
    if value:
        return value.strftime(format)
    return ""

# Register the custom filter
templates.env.filters["datetime"] = format_datetime


# GLOBAL TRANSLATION FUNCTION
# We use @jinja2.pass_context to give the function access to the current template context.
# This allows us to automatically read the language from request.state.lang 
# without having to monkey-patch TemplateResponse or pass it manually from every route.
@jinja2.pass_context
def global_translate(context, key: str) -> str:
    request = context.get("request")
    if request and hasattr(request.state, "lang"):
        lang = request.state.lang
    else:
        lang = "en"
    return translate_func(key, lang)

# Inject the translation function and languages dictionary globally into ALL templates
templates.env.globals["t"] = global_translate
templates.env.globals["languages"] = {'en': 'English', 'fr': 'Français'}