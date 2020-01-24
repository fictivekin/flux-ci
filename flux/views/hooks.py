# Copyright (c) 2016  Niklas Rosenstein
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from flux import app, config, file_utils, models, utils
from flux.build import enqueue, terminate_build
from flux.models import (
    User,
    LoginToken,
    Repository,
    Build,
    get_target_for,
    select,
    desc,
)
from flux.utils import secure_filename
from flask import request, session, redirect, url_for, render_template, Blueprint
from datetime import datetime

import json
import os
import uuid

API_CONTENTFUL = "contentful"
API_GOGS = "gogs"
API_GITHUB = "github"
API_GITEA = "gitea"
API_GITBUCKET = "gitbucket"
API_BITBUCKET = "bitbucket"
API_BITBUCKET_CLOUD = "bitbucket-cloud"
API_GITLAB = "gitlab"
API_BARE = "bare"

hooks_bp = Blueprint("hooks", __name__)


@hooks_bp.route("/bare", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def bare(data, logger):
    owner = utils.get(data, "owner", str)
    name = utils.get(data, "name", str)
    ref = utils.get(data, "ref", str)
    commit = utils.get(data, "commit", str)
    secret = utils.get(data, "secret", str)
    get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/contentful", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def contentful(data, logger):
    owner = request.headers.get("X-Contentful-Owner")
    name = request.headers.get("X-Contentful-Repo")
    ref = request.headers.get("X-Contentful-Branch")
    # A dummy commit, since Contentful can't know which hash is current
    commit = ("0" * 32)
    secret = request.headers.get("X-Contentful-Token")
    get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/bitbucket-cloud", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def bitbucket_cloud(data, logger):
    event = request.headers.get("X-Event-Key")
    if event != "repo:push":
        logger.error(
            "Payload rejected (expected 'repo:push' event, got {!r})".format(event)
        )
        return 400
    owner = utils.get(data, "repository.project.project", str)
    name = utils.get(data, "repository.name", str)

    ref_type = utils.get(data, "push.changes.0.new.type", str)
    ref_name = utils.get(data, "push.changes.0.new.name", str)
    ref = "refs/" + ("heads/" if ref_type == "branch" else "tags/") + ref_name

    commit = utils.get(data, "push.changes.0.new.target.hash", str)
    secret = None
    get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/bitbucket", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def bitbucket(data, logger):
    event = request.headers.get("X-Event-Key")
    if event != "repo:refs_changed":
        logger.error(
            "Payload rejected (expected 'repo:refs_changed' event, got {!r})".format(
                event
            )
        )
        return 400
    owner = utils.get(data, "repository.project.name", str)
    name = utils.get(data, "repository.name", str)
    ref = utils.get(data, "changes.0.refId", str)
    commit = utils.get(data, "changes.0.toHash", str)
    secret = request.headers.get("X-Hub-Signature", "").replace("sha256=", "")
    if secret:
        get_repo_secret = lambda r: utils.get_bitbucket_signature(
            r.secret, request.data
        )
    else:
        get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/gitbucket", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def gitbucket(data, logger):
    event = request.headers.get("X-Github-Event")
    if event != "push":
        logger.error("Payload rejected (expected 'push' event, got {!r})".format(event))
        return 400
    owner = utils.get(data, "repository.owner.login", str)
    name = utils.get(data, "repository.name", str)
    ref = utils.get(data, "ref", str)
    commit = utils.get(data, "after", str)
    secret = request.headers.get("X-Hub-Signature", "").replace("sha1=", "")
    if secret:
        get_repo_secret = lambda r: utils.get_github_signature(r.secret, request.data)
    else:
        get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/gitea", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def gitea(data, logger):
    event = request.headers.get("X-Gitea-Event")
    if event != "push":
        logger.error("Payload rejected (expected 'push' event, got {!r})".format(event))
        return 400
    owner = utils.get(data, "repository.owner.username", str)
    name = utils.get(data, "repository.name", str)
    ref = utils.get(data, "ref", str)
    commit = utils.get(data, "after", str)
    secret = utils.get(data, "secret", str)
    get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/gogs", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def gogs(data, logger):
    owner = utils.get(data, "repository.owner.username", str)
    name = utils.get(data, "repository.name", str)
    ref = utils.get(data, "ref", str)
    commit = utils.get(data, "after", str)
    secret = utils.get(data, "secret", str)
    get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/gitlab", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def gitlab(data, logger):
    event = utils.get(data, "object_kind", str)
    if event != "push" and event != "tag_push":
        logger.error(
            "Payload rejected (expected 'push' or 'tag_push' event, got {!r})".format(
                event
            )
        )
        return 400
    owner = utils.get(data, "project.namespace", str)
    name = utils.get(data, "project.name", str)
    ref = utils.get(data, "ref", str)
    commit = utils.get(data, "checkout_sha", str)
    secret = request.headers.get("X-Gitlab-Token")
    get_repo_secret = lambda r: r.secret

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


@hooks_bp.route("/github", methods=["POST"])
@utils.with_io_response(mimetype="text/plain")
@utils.with_logger()
@utils.with_req_data()
@models.session
def github(data, logger):
    event = request.headers.get("X-Github-Event")
    if event != "push":
        logger.error("Payload rejected (expected 'push' event, got {!r})".format(event))
        return 400
    owner = utils.get(data, "repository.owner.name", str)
    name = utils.get(data, "repository.name", str)
    ref = utils.get(data, "ref", str)
    commit = utils.get(data, "after", str)
    secret = request.headers.get("X-Hub-Signature", "").replace("sha1=", "")
    get_repo_secret = lambda r: utils.get_github_signature(r.secret, request.data)

    return process_hook(name, owner, ref, commit, secret, get_repo_secret, logger)


def process_hook(name, owner, ref, commit, secret, get_repo_secret, logger):

    if not name:
        logger.error("invalid JSON: no repository name received")
        return 400
    if not owner:
        logger.error("invalid JSON: no repository owner received")
        return 400
    if not ref:
        logger.error("invalid JSON: no Git ref received")
        return 400
    if not commit:
        logger.error("invalid JSON: no commit SHA received")
        return 400
    if len(commit) != 40 and len(commit) != 32:
        logger.error("invalid JSON: commit SHA has invalid length")
        return 400
    if secret == None:
        secret = ""

    name = owner + "/" + name

    repo = Repository.get(name=name)
    if not repo:
        logger.error("PUSH event rejected (unknown repository)")
        return 400
    if get_repo_secret(repo) != secret:
        logger.error("PUSH event rejected (invalid secret)")
        return 400
    if not repo.check_accept_ref(ref):
        logger.info("Git ref {!r} not whitelisted. No build dispatched".format(ref))
        return 200

    # Need to check for an existing queued build before terminating a hung build, so that
    # a previously queued build does not immediately start after the hung build gets terminated
    # and then we queue up another build uselessly.
    existing_build = Build.select(
        lambda x: (x.status == Build.Status_Queued and
                   x.commit_sha == commit and
                   x.ref == ref and
                   x.repo == repo)).first()

    hung_build_limit = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=15)
    hung_build = Build.select(
        lambda x: (x.status == Build.Status_Building and
                   x.ref == ref and
                   x.date_started < hung_build_limit and
                   x.repo == repo)).first()
    if hung_build:
        terminate_build(hung_build)

    if existing_build:
        # We found an existing queued build with the same details, so skip out without queuing another
        logger.info("Queued build found for the same repo with the same ref and commit sha")
        return 200

    build = Build(
        repo=repo,
        commit_sha=commit,
        num=repo.build_count,
        ref=ref,
        status=Build.Status_Queued,
        date_queued=datetime.now(),
        date_started=None,
        date_finished=None,
    )
    repo.build_count += 1

    models.commit()
    enqueue(build)
    logger.info("Build #{} for repository {} queued".format(build.num, repo.name))
    logger.info(utils.strip_url_path(config.app_url) + build.url())
    return 200
