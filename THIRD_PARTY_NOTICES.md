# Third-Party Notices

This inventory covers the public source tree. It is not a legal opinion and
does not replace the license files shipped by upstream projects. Versions are
pinned in `requirements-dev.lock` and `apps/web/package-lock.json`.

## Knowledge and data

- **MITRE ATT&CK Enterprise 18.1**: selected technique, detection strategy,
  analytics and data-component objects under
  `knowledge/attack-18.1/source-objects.json`. Source commit, URLs and SHA-256
  are in `knowledge/attack-18.1/source.json`; the MITRE license text is in
  `knowledge/attack-18.1/LICENSE.txt`. The MITRE license applies to that
  material, not to the whole repository.
- **Synthetic fixtures** under `data/fixtures/`: generated for this project;
  no real host, account, packet payload or third-party capture is included.
  Each fixture has a manifest with source and hashes.
- **CTU-13 / CICIoT2023 materials** referenced by historical evaluation notes
  are not included in this public source snapshot. Their original terms must be
  checked before any separate redistribution.

## Python runtime and development dependencies

The following are installed from the locked versions and remain under their
upstream licenses (typically MIT/BSD/Apache-2.0; verify the package metadata):

- FastAPI, Starlette, Uvicorn, Pydantic, pydantic-settings, SQLAlchemy, Alembic
- psycopg / psycopg-binary, python-multipart, httpx, anyio, h11, httpcore
- pytest, pluggy, iniconfig, packaging, Pygments, Ruff
- Mako, MarkupSafe, python-dotenv, typing-extensions, annotated-types
- opentelemetry-api, certifi, idna, click, colorama, tzdata

## JavaScript/TypeScript frontend

- React, React DOM (MIT)
- Vite (MIT), TypeScript (Apache-2.0), ESLint and typescript-eslint (MIT/BSD)
- json-schema-to-typescript (MIT), Playwright (Apache-2.0)
- @types packages ( DefinitelyTyped licenses, typically MIT)

## Fonts, icons and screenshots

No bundled third-party fonts or icon packs were identified in the source tree.
Screenshots, if added later, must be checked for embedded third-party marks and
personal data before publication.

## Pending review

See `LICENSE-STATUS.md`. This inventory must be updated when a dependency,
knowledge object, fixture, screenshot or demonstration asset is added.