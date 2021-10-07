#!/usr/bin/env python
import argparse
import logging
import tempfile
import sys
import os

import koji
from koji_cli.lib import (
    activate_session,
    download_rpm,
)

import rpm_head_signing.fix_signatures


def parse_args():
    parser = argparse.ArgumentParser(description="Mass IMA signature fixer")

    parser.add_argument("--sig-key-id", required=True)
    parser.add_argument("--update-live", action="store_true")

    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--debug", action="store_true")

    koji_options = parser.add_argument_group("Koji options")
    koji_options.add_argument("--koji-profile", default="koji")
    koji_options.add_argument("--koji-config-file")

    builds_options = parser.add_argument_group("Build selections")
    builds_options.add_argument(
        "--selection-type", choices=("builds", "tag"), required=True
    )
    builds_options.add_argument("selections", nargs="*")

    return parser.parse_args()


def get_koji_session(args):
    result = koji.read_config(args.koji_profile, args.koji_config_file)
    logging.debug("Koji profile: %s", result)
    koji_session = koji.ClientSession(result["server"], opts=result)
    logging.debug("Koji session: %s", koji_session)
    if args.update_live:
        logging.info("Activating koji session")
        activate_session(koji_session, result)
        logging.info(
            "Session activated, logged in as: %s", koji_session.getLoggedInUser()
        )
    else:
        logging.info("Not updating live, so not activating session")
    return koji_session, result


def get_builds(args, koji_session):
    if args.selection_type == "builds":
        for build in args.selections:
            yield koji_session.getBuild(build)
    elif args.selection_type == "tag":
        res = koji_session.listTagged(args.selections[0])
        for build in res:
            yield build
    else:
        raise ValueError("Unknown selection type: %s" % args.selection_type)


def main(args):
    if args.update_live:
        logging.error("UPDATING LIVE")
    else:
        logging.error("Dry run")

    logging.debug("Arguments: %s", args)

    if len(args.selections) == 0:
        raise Exception("No build selected")
    if args.selection_type == "tag" and len(args.selections) > 1:
        raise Exception("Multiple tags selected")

    koji_session, koji_options = get_koji_session(args)
    builds = get_builds(args, koji_session)

    pi = koji.PathInfo(topdir=koji_options["topurl"])

    for build in builds:
        logging.info("Processing build %s", build["build_id"])
        try:
            rpms = koji_session.listRPMs(buildID=build["build_id"])
            logging.debug("Rpms: %s", rpms)
            with koji_session.multicall() as m:
                results = [
                    m.queryRPMSigs(rpm_id=r["id"], sigkey=args.sig_key_id) for r in rpms
                ]
            rpm_keys = [x.result for x in results]
            for rpm, rpm_key in list(zip(rpms, rpm_keys)):
                if not rpm_key:
                    nvra = "%(nvr)s-%(arch)s.rpm" % rpm
                    logging.error("No signature for %s", nvra)
                    rpms.remove(rpm)

            for rpm in rpms:
                nvra = "%(nvr)s-%(arch)s.rpm" % rpm
                logging.info("Downloading signed copy of %s", nvra)
                download_rpm(
                    build,
                    rpm,
                    koji_options["topurl"],
                    sigkey=args.sig_key_id,
                    quiet=args.quiet,
                    noprogress=False,
                )

                fname = pi.signed(rpm, args.sig_key_id)
                fname = os.path.basename(fname)

                changed = rpm_head_signing.fix_signatures.fix_ima_signatures(
                    fname, dry_run=False
                )

                if not changed:
                    logging.info("RPM %s had no issues")
                else:
                    descrip = []
                    if (
                        changed
                        & rpm_head_signing.fix_signatures.CHANGED_IMA_SIG_BYTEORDER
                    ):
                        descrip.append("byteorder")
                    if changed & rpm_head_signing.fix_signatures.CHANGED_IMA_SIG_LENGTH:
                        descrip.append("length")
                    logging.info(
                        "RPM %s had issues fixed: %s", nvra, ", ".join(descrip)
                    )

                    data = koji.get_header_fields(
                        fname,
                        (
                            "siggpg",
                            "sigpgp",
                            "dsaheader",
                            "rsaheader",
                        ),
                    )
                    sigkey = data["siggpg"]
                    if not sigkey:
                        sigkey = data["sigpgp"]
                    if not sigkey:
                        sigkey = data["dsaheader"]
                    if not sigkey:
                        sigkey = data["rsaheader"]
                    if not sigkey:
                        raise Exception("Not signed?")
                    else:
                        sigkey = koji.get_sigpacket_key_id(sigkey)
                    if sigkey != args.sig_key_id:
                        raise Exception("Computed sigkey does not match provided: %s != %s" % (sigkey, args.sig_key_id))
                    del data["siggpg"]
                    del data["sigpgp"]
                    del data["dsaheader"]
                    del data["rsaheader"]
                    sighdr = koji.rip_rpm_sighdr(fname)

                    if not args.update_live:
                        logging.info("Not updating live, so not uploading")
                    else:
                        logging.info("Deleting current signature")
                        koji_session.deleteRPMSig(rpm["id"], sigkey=args.sig_key_id)

                        logging.info("Uploading new signature")
                        koji_session.addRPMSig(rpm["id"], base64encode(sighdr))

                        logging.info("Writing signed copy")
                        koji_session.writeSignedRPM(rpm["id"], sigkey)

        except Exception:
            logging.exception("Error processing build")


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO)

    working_dir = os.getcwd()
    try:
        with tempfile.TemporaryDirectory(prefix="ima-mass-fixer-") as tmpdir:
            logging.debug("Temporary directory: %s", tmpdir)
            os.chdir(tmpdir)
            main(parse_args())
    finally:
        os.chdir(working_dir)
