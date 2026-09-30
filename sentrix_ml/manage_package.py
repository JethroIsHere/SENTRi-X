"""Model candidate package management CLI: validate, activate, rollback, and status.

Features:
- validate: verify file existence, schema alignment, and SHA256 checksums
- activate: validate candidate, backup current active models, install into active candidate slot
- rollback: restore from a previous backup
- status: inspect candidate packages and active backend deployment state

Usage:
    python -m sentrix_ml.manage_package validate models/candidates/smoke_v2
    python -m sentrix_ml.manage_package activate models/candidates/omni_v2 --target omni
    python -m sentrix_ml.manage_package rollback
    python -m sentrix_ml.manage_package status
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from sentrix_ml.packaging import validate_package, ModelManifest, PackageValidationError


def cmd_validate(candidate_dir: str):
    path = Path(candidate_dir)
    print(f"Validating candidate package in: {path}")
    try:
        manifest = validate_package(path)
        print("=" * 60)
        print("STATUS: VALID")
        print(f"Package Version: {manifest.package_version}")
        print(f"Schema Version:  {manifest.schema_version}")
        print(f"Domain:          {manifest.domain}")
        print(f"Run Type:        {manifest.evaluation_run_type}")
        print(f"RF Hash:         {manifest.rf_hash}")
        print(f"CNN Hash:        {manifest.cnn_hash}")
        print(f"Pipeline Hash:   {manifest.preprocessor_hash}")
        if manifest.evaluation_hash:
            print(f"Evaluation Hash: {manifest.evaluation_hash}")
        print("=" * 60)
        return True
    except PackageValidationError as e:
        print("=" * 60)
        print(f"STATUS: INVALID - {e}")
        print("=" * 60)
        return False


def cmd_activate(candidate_dir: str, target: str):
    candidate_path = Path(candidate_dir).resolve()
    print(f"Activating candidate '{candidate_path}' for target slot '{target}'...")

    # 1. Validate candidate first (strict deployable check)
    try:
        manifest = validate_package(candidate_path, strict_deployable=True, target_domain=target)
    except PackageValidationError as e:
        print(f"ACTIVATION ABORTED: Package validation failed: {e}")
        return False

    project_root = Path(__file__).resolve().parent.parent
    dest_dir = project_root / "models" / "candidates" / target
    backup_base = project_root / "models" / "backups"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_dir = backup_base / f"{target}_{timestamp}"

    # 2. Backup existing candidate if present
    if dest_dir.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        print(f"Backing up existing '{target}' candidate to: {backup_dir}")
        for item in dest_dir.iterdir():
            if item.is_file():
                shutil.copy2(item, backup_dir / item.name)

    # 3. Copy candidate files to active slot
    dest_dir.mkdir(parents=True, exist_ok=True)
    for item in candidate_path.iterdir():
        if item.is_file():
            shutil.copy2(item, dest_dir / item.name)

    # 4. Verify activated candidate
    validate_package(dest_dir)
    print("=" * 60)
    print(f"SUCCESS: Candidate activated in {dest_dir}")
    print(f"Backend can now load this model via target='{target}'")
    print(f"Backup preserved at: {backup_dir}")
    print("=" * 60)
    return True


def cmd_rollback(target: str, backup_dir: str | None = None):
    project_root = Path(__file__).resolve().parent.parent
    dest_dir = project_root / "models" / "candidates" / target
    backup_base = project_root / "models" / "backups"

    if backup_dir:
        src = Path(backup_dir)
    else:
        # Find latest backup for this target
        if not backup_base.exists():
            print("No backups found.")
            return False
        matches = sorted([d for d in backup_base.iterdir() if d.is_dir() and d.name.startswith(f"{target}_")])
        if not matches:
            print(f"No backups found for target '{target}'.")
            return False
        src = matches[-1]

    print(f"Rolling back '{target}' from backup: {src}")
    if not (src / "manifest.json").exists():
        print(f"ROLLBACK ABORTED: Missing manifest.json in backup {src}")
        return False

    validate_package(src)
    dest_dir.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.is_file():
            shutil.copy2(item, dest_dir / item.name)

    validate_package(dest_dir)
    print("=" * 60)
    print(f"ROLLBACK SUCCESS: Target '{target}' restored from {src}")
    print("=" * 60)
    return True


def cmd_status():
    project_root = Path(__file__).resolve().parent.parent
    candidates_dir = project_root / "models" / "candidates"
    backup_base = project_root / "models" / "backups"

    print("=" * 70)
    print("                 SENTRi-X Model Candidates Status")
    print("=" * 70)

    if candidates_dir.exists():
        candidates = sorted([d for d in candidates_dir.iterdir() if d.is_dir()])
        print(f"\nFound {len(candidates)} candidate packages in models/candidates/:")
        for c in candidates:
            manifest_path = c / "manifest.json"
            if manifest_path.exists():
                try:
                    m = validate_package(c)
                    print(f"  * {c.name:20s}: VALID   [domain={m.domain}, run_type={m.evaluation_run_type}]")
                except PackageValidationError as e:
                    print(f"  * {c.name:20s}: INVALID [{e}]")
            else:
                print(f"  * {c.name:20s}: NO MANIFEST")
    else:
        print("\nNo candidates directory found.")

    if backup_base.exists():
        backups = sorted([d for d in backup_base.iterdir() if d.is_dir()])
        print(f"\nFound {len(backups)} backups in models/backups/:")
        for b in backups[-5:]:
            print(f"  - {b.name}")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="SENTRi-X Package Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Validate
    val_p = subparsers.add_parser("validate", help="Validate a candidate package")
    val_p.add_argument("candidate_dir", help="Path to candidate directory")

    # Activate
    act_p = subparsers.add_parser("activate", help="Activate candidate into a deployment slot")
    act_p.add_argument("candidate_dir", help="Path to candidate directory")
    act_p.add_argument("--target", required=True, choices=["omni", "ton_iot", "bot_iot", "cic_ids2017", "smoke_v2"], help="Deployment slot")

    # Rollback
    rb_p = subparsers.add_parser("rollback", help="Roll back an active deployment slot to previous backup")
    rb_p.add_argument("--target", required=True, help="Deployment slot")
    rb_p.add_argument("--backup-dir", default=None, help="Explicit backup directory (defaults to latest)")

    # Status
    subparsers.add_parser("status", help="Show all candidates and backups")

    args = parser.parse_args()
    if args.command == "validate":
        success = cmd_validate(args.candidate_dir)
        sys.exit(0 if success else 1)
    elif args.command == "activate":
        success = cmd_activate(args.candidate_dir, args.target)
        sys.exit(0 if success else 1)
    elif args.command == "rollback":
        success = cmd_rollback(args.target, args.backup_dir)
        sys.exit(0 if success else 1)
    elif args.command == "status":
        cmd_status()


if __name__ == "__main__":
    main()
