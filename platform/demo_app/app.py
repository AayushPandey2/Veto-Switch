"""Flask application factory for the Veto-Switch demo."""

from flask import Flask, Response, jsonify, request

from demo_app.config import DemoSettings
from demo_app.database import initialize_database, seed_demo_data
from demo_app.feature_flags import LocalFeatureFlagProvider
from demo_app.file_service import read_public_demo_file
from demo_app.search_service import search_documents
from demo_app.vulnerable_file_service import (
    vulnerable_read_demo_file_for_demo,
)
from demo_app.vulnerable_search_service import (
    vulnerable_search_documents_for_demo,
)


def _validate_search_query() -> str | Response:
    """Return a normalized query or an HTTP 400 response for invalid input."""
    query = request.args.get("q", "").strip()

    if not query:
        response = jsonify({"error": "Query parameter 'q' is required."})
        response.status_code = 400
        return response

    if len(query) > 100:
        response = jsonify({"error": "Search query must be 100 characters or fewer."})
        response.status_code = 400
        return response

    return query


def _validate_file_path() -> str | Response:
    """Return a normalized file path or an HTTP 400 response."""
    file_path = request.args.get("path", "").strip()

    if not file_path:
        response = jsonify({"error": "Query parameter 'path' is required."})
        response.status_code = 400
        return response

    if len(file_path) > 256:
        response = jsonify({"error": "File path must be 256 characters or fewer."})
        response.status_code = 400
        return response

    return file_path


def create_app(settings: DemoSettings | None = None) -> Flask:
    """Create a configured demonstration application."""
    settings = settings or DemoSettings.from_env()

    app = Flask(__name__)
    app.config["DEMO_SETTINGS"] = settings

    app.extensions["feature_flags"] = LocalFeatureFlagProvider(
        demo_mode=settings.demo_mode,
        allow_vulnerable_routes=settings.allow_vulnerable_routes,
    )

    initialize_database(settings.database_path)
    seed_demo_data(settings.database_path)
    app.extensions["database_path"] = settings.database_path

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "healthy",
                "service": "veto-switch-demo",
                "environment": settings.environment,
            }
        )

    @app.get("/status")
    def status():
        """Represent an unrelated healthy route during search containment."""
        return jsonify({"status": "operational", "service": "veto-switch-demo"})

    @app.get("/search")
    def search():
        query = _validate_search_query()
        if isinstance(query, Response):
            return query

        feature_flags: LocalFeatureFlagProvider = app.extensions["feature_flags"]
        if feature_flags.is_enabled("search_v2"):
            results = search_documents(
                app.extensions["database_path"],
                query,
            )
            return jsonify(
                {
                    "variant": "search_v2",
                    "count": len(results),
                    "results": results,
                }
            )

        if feature_flags.is_enabled("search_v1"):
            results = vulnerable_search_documents_for_demo(
                app.extensions["database_path"],
                query,
            )
            return jsonify(
                {
                    "variant": "search_v1",
                    "warning": "Intentionally vulnerable local demonstration.",
                    "count": len(results),
                    "results": results,
                }
            )

        results = search_documents(
            app.extensions["database_path"],
            query,
        )
        return jsonify(
            {
                "variant": "safe_fallback",
                "count": len(results),
                "results": results,
            }
        )

    @app.get("/demo/search-v1")
    def vulnerable_search_demo():
        """Expose the unsafe search only behind all explicit local demo gates."""
        feature_flags: LocalFeatureFlagProvider = app.extensions["feature_flags"]
        if not feature_flags.is_enabled("search_v1") or feature_flags.is_enabled(
            "search_v2"
        ):
            return jsonify({"error": "Not found."}), 404

        query = _validate_search_query()
        if isinstance(query, Response):
            return query

        results = vulnerable_search_documents_for_demo(
            app.extensions["database_path"],
            query,
        )
        return jsonify(
            {
                "warning": "Intentionally vulnerable local demonstration endpoint.",
                "count": len(results),
                "results": results,
            }
        )

    @app.get("/files")
    def files():
        file_path = _validate_file_path()
        if isinstance(file_path, Response):
            return file_path

        feature_flags: LocalFeatureFlagProvider = app.extensions["feature_flags"]
        if feature_flags.is_enabled("files_v2"):
            variant = "files_v2"
            content = read_public_demo_file(file_path)
        elif feature_flags.is_enabled("files_v1"):
            variant = "files_v1"
            content = vulnerable_read_demo_file_for_demo(file_path)
        else:
            variant = "safe_fallback"
            content = read_public_demo_file(file_path)

        if content is None:
            return jsonify({"error": "File not found."}), 404

        payload = {
            "variant": variant,
            "path": file_path,
            "content": content,
        }
        if variant == "files_v1":
            payload["warning"] = "Intentionally vulnerable local demonstration."

        return jsonify(payload)

    @app.get("/demo/files-v1")
    def vulnerable_file_demo():
        """Expose path traversal only against predefined synthetic demo files."""
        feature_flags: LocalFeatureFlagProvider = app.extensions["feature_flags"]
        if not feature_flags.is_enabled("files_v1") or feature_flags.is_enabled(
            "files_v2"
        ):
            return jsonify({"error": "Not found."}), 404

        file_path = _validate_file_path()
        if isinstance(file_path, Response):
            return file_path

        content = vulnerable_read_demo_file_for_demo(file_path)
        if content is None:
            return jsonify({"error": "File not found."}), 404

        return jsonify(
            {
                "warning": "Synthetic path traversal demonstration; no disk files are read.",
                "path": file_path,
                "content": content,
            }
        )

    return app
