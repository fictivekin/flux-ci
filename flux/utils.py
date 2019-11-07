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

import io
import functools
import hashlib
import hmac
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import urllib.parse
import uuid
import werkzeug
import zipfile

from . import app, config, models
from urllib.parse import urlparse
from flask import request, session, redirect, url_for, Response
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def get_raise(data, key, expect_type=None):
    """ Helper function to retrieve an element from a JSON data structure.
  The *key* must be a string and may contain periods to indicate nesting.
  Parts of the key may be a string or integer used for indexing on lists.
  If *expect_type* is not None and the retrieved value is not of the
  specified type, TypeError is raised. If the key can not be found,
  KeyError is raised. """

    parts = key.split(".")
    resolved = ""
    for part in parts:
        resolved += part
        try:
            part = int(part)
        except ValueError:
            pass

        if isinstance(part, str):
            if not isinstance(data, dict):
                raise TypeError("expected dictionary to access {!r}".format(resolved))
            try:
                data = data[part]
            except KeyError:
                raise KeyError(resolved)
        elif isinstance(part, int):
            if not isinstance(data, list):
                raise TypeError("expected list to access {!r}".format(resolved))
            try:
                data = data[part]
            except IndexError:
                raise KeyError(resolved)
        else:
            assert False, "unreachable"

        resolved += "."

    if expect_type is not None and not isinstance(data, expect_type):
        raise TypeError(
            "expected {!r} but got {!r} instead for {!r}".format(
                expect_type.__name__, type(data).__name__, key
            )
        )
    return data


def get(data, key, expect_type=None, default=None):
    """ Same as :func:`get_raise`, but returns *default* if the key could
  not be found or the datatype doesn't match. """

    try:
        return get_raise(data, key, expect_type)
    except (TypeError, ValueError):
        return default


def basic_auth(message="Login required"):
    """ Sends a 401 response that enables basic auth. """

    headers = {"WWW-Authenticate": 'Basic realm="{}"'.format(message)}
    return Response("Please log in.", 401, headers, mimetype="text/plain")


def requires_auth(func):
    """ Decorator for view functions that require basic authentication. """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        token_string = session.get("flux_login_token")
        token = models.LoginToken.select(lambda t: t.token == token_string).first()
        if not token or token.ip != ip or token.expired():
            if token and token.expired():
                flash("Your login session has expired.")
                token.delete()
            return redirect(url_for("login"))

        request.login_token = token
        request.user = token.user
        return func(*args, **kwargs)

    return wrapper


def with_io_response(kwarg="stream", stream_type="text", **response_kwargs):
    """ Decorator for View functions that create a :class:`io.StringIO` or
  :class:`io.BytesIO` (based on the *stream_type* parameter) and pass it
  as *kwarg* to the wrapped function. The contents of the buffer are
  sent back to the client. """

    if stream_type == "text":
        factory = io.StringIO
    elif stream_type == "bytes":
        factory = io.BytesIO
    else:
        raise ValueError("invalid value for stream_type: {!r}".format(stream_type))

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if kwarg in kwargs:
                raise RuntimeError(
                    "keyword argument {!r} already occupied".format(kwarg)
                )
            kwargs[kwarg] = stream = factory()
            status = func(*args, **kwargs)
            return Response(stream.getvalue(), status=status, **response_kwargs)

        return wrapper

    return decorator


def with_logger(kwarg="logger", stream_dest_kwarg="stream", replace=True):
    """ Decorator that creates a new :class:`logging.Logger` object
  additionally to or in-place for the *stream* parameter passed to
  the wrapped function. This is usually used in combination with
  the :func:`with_io_response` decorator.

  Note that exceptions with this decorator will be logged and the
  returned status code will be 500 Internal Server Error. """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if replace:
                stream = kwargs.pop(stream_dest_kwarg)
            else:
                stream = kwargs[stream_dest_kwarg]
            kwargs[kwarg] = logger = create_logger(stream)
            try:
                return func(*args, **kwargs)
            except BaseException as exc:
                logger.exception(exc)
                return 500

        return wrapper

    return decorator


def create_logger(stream, name=__name__, fmt=None):
    """ Creates a new :class:`logging.Logger` object with the
  specified *name* and *fmt* (defaults to a standard logging
  formating including the current time, levelname and message).

  The logger will also output to stderr. """

    fmt = fmt or "[%(asctime)-15s - %(levelname)s]: %(message)s"
    formatter = logging.Formatter(fmt)

    logger = logging.Logger(name)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def stream_file(filename, name=None, mime=None):
    def generate():
        with open(filename, "rb") as fp:
            yield from fp

    if name is None:
        name = os.path.basename(filename)
    headers = {}
    headers["Content-Type"] = mime or "application/x-octet-stream"
    headers["Content-Length"] = os.stat(filename).st_size
    headers["Content-Disposition"] = 'attachment; filename="' + name + '"'
    return Response(generate(), 200, headers)


def flash(message=None):
    if message is None:
        return session.pop("flux_flash", None)
    else:
        session["flux_flash"] = message


def make_secret():
    return str(uuid.uuid4())


def hash_pw(pw):
    return hashlib.md5(pw.encode("utf8")).hexdigest()


def makedirs(path):
    """ Shorthand that creates a directory and stays silent when it
  already exists. """

    if not os.path.exists(path):
        os.makedirs(path)


def rmtree(path, remove_write_protection=False):
    """
  A wrapper for #shutil.rmtree() that can try to remove write protection
  if removing fails, if enabled.
  """

    if remove_write_protection:

        def on_rm_error(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            os.unlink(path)

    else:
        on_rm_error = None

    shutil.rmtree(path, onerror=on_rm_error)


def zipdir(dirname, filename):
    dirname = os.path.abspath(dirname)
    zipf = zipfile.ZipFile(filename, "w")
    for root, dirs, files in os.walk(dirname):
        for fname in files:
            arcname = os.path.join(os.path.relpath(root, dirname), fname)
            zipf.write(os.path.join(root, fname), arcname)
    zipf.close()


def secure_filename(filename):
    """
  Similar to #werkzeug.secure_filename(), but preserves leading dots in
  the filename.
  """

    while True:
        filename = filename.lstrip("/").lstrip("\\")
        if filename.startswith("..") and filename[2:3] in "/\\":
            filename = filename[3:]
        elif filename.startswith(".") and filename[1:2] in "/\\":
            filename = filename[2:]
        else:
            break

    has_dot = filename.startswith(".")
    filename = werkzeug.secure_filename(filename)
    if has_dot:
        filename = "." + filename
    return filename


def quote(s, for_ninja=False):
    """
  Enhanced implementation of #shlex.quote().
  Does not generate single-quotes on Windows.
  """

    if os.name == "nt" and os.sep == "\\":
        s = s.replace('"', '\\"')
        if re.search("\s", s) or any(c in s for c in "<>"):
            s = '"' + s + '"'
    else:
        s = shlex.quote(s)
    return s


def run(
    command,
    logger,
    cwd=None,
    env=None,
    shell=False,
    return_stdout=False,
    inherit_env=True,
):
    """
  Run a subprocess with the specified command. The command and output of is
  logged to logger. The command will automatically be converted to a string
  or list of command arguments based on the *shell* parameter.

  # Parameters
  command (str, list): A command-string or list of command arguments.
  logger (logging.Logger): A logger that will receive the command output.
  cwd (str, None): The current working directory.
  env (dict, None): The environment for the subprocess.
  shell (bool): If set to #True, execute the command via the system shell.
  return_stdout (bool): Return the output of the command (including stderr)
      to the caller. The result will be a tuple of (returncode, output).
  inherit_env (bool): Inherit the current process' environment.

  # Return
  int, tuple of (int, str): The return code, or the returncode and the
      output of the command.
  """

    if shell:
        if not isinstance(command, str):
            command = " ".join(quote(x) for x in command)
        if logger:
            logger.info("$ " + command)
    else:
        if isinstance(command, str):
            command = shlex.split(command)
        if logger:
            logger.info("$ " + " ".join(map(quote, command)))

    if env is None:
        env = {}
    if inherit_env:
        env = {**os.environ, **env}

    popen = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=None,
    )
    stdout = popen.communicate()[0].decode()
    if stdout:
        if popen.returncode != 0 and logger:
            logger.error("\n" + stdout)
        else:
            if logger:
                logger.info("\n" + stdout)
    if return_stdout:
        return popen.returncode, stdout
    return popen.returncode


def ssh_command(
    url, *args, no_ptty=False, identity_file=None, verbose=None, options=None
):
    """ Helper function to generate an SSH command. If not options are
  specified, the default option ``BatchMode=yes`` will be set. """

    if options is None:
        options = {"BatchMode": "yes"}
    if verbose is None:
        verbose = config.ssh_verbose

    command = ["ssh"]
    if url is not None:
        command.append(url)
    command += ["-o{}={}".format(k, v) for (k, v) in options.items()]
    if no_ptty:
        command.append("-T")
    if identity_file:
        command += ["-o", "IdentitiesOnly=yes"]
        # NOTE: Workaround for windows, as the backslashes are gone at the time
        #   Git tries to use the GIT_SSH_COMMAND.
        command += ["-i", identity_file.replace("\\", "/")]
    if verbose:
        command.append("-v")
    if args:
        command.append("--")
        command += args
    return command


def strip_url_path(url):
    """ Strips that path part of the specified *url*. """

    result = list(urllib.parse.urlparse(url))
    result[2] = ""
    return urllib.parse.urlunparse(result)


def get_github_signature(secret, payload_data):
    """ Generates the Github HMAC signature from the repository
  *secret* and the *payload_data*. The GitHub signature is sent
  with the ``X-Hub-Signature`` header. """

    return hmac.new(secret.encode("utf8"), payload_data, hashlib.sha1).hexdigest()


def get_bitbucket_signature(secret, payload_data):
    """ Generates the Bitbucket HMAC signature from the repository
  *secret* and the *payload_data*. The Bitbucket signature is sent
  with the ``X-Hub-Signature`` header. """

    return hmac.new(secret.encode("utf8"), payload_data, hashlib.sha256).hexdigest()


def get_date_diff(date1, date2):
    if (not date1) or (not date2):
        if (not date1) and date2:
            date1 = datetime.now()
        else:
            return "00:00:00"
    diff = (date1 - date2) if date1 > date2 else (date2 - date1)
    seconds = int(diff.seconds % 60)
    minutes = int(((diff.seconds - seconds) / 60) % 60)
    hours = int((diff.seconds - seconds - minutes * 60) / 3600)
    return "{:02d}:{:02d}:{:02d}".format(hours, minutes, seconds)


def is_page_active(page, user):
    path = request.path

    if page == "dashboard" and (not path or path == "/"):
        return True
    elif page == "repositories" and (
        path.startswith("/repositories")
        or path.startswith("/repo")
        or path.startswith("/edit/repo")
        or path.startswith("/build")
        or path.startswith("/overrides")
    ):
        return True
    elif page == "users" and (
        path.startswith("/users")
        or (path.startswith("/user") and path != ("/user/" + str(user.id)))
    ):
        return True
    elif page == "profile" and path == ("/user/" + str(user.id)):
        return True
    elif page == "integration" and path == "/integration":
        return True
    return False


def ping_repo(repo_url, repo=None):
    if not repo_url or repo_url == "":
        return 1

    if repo and os.path.isfile(get_repo_private_key_path(repo)):
        identity_file = get_repo_private_key_path(repo)
    else:
        identity_file = config.ssh_identity_file

    ssh_cmd = ssh_command(None, identity_file=identity_file)
    env = {"GIT_SSH_COMMAND": " ".join(map(quote, ssh_cmd))}
    ls_remote = ["git", "ls-remote", "--exit-code", repo_url]
    res = run(ls_remote, app.logger, env=env)
    return res


def get_customs_path(repo):
    return os.path.join(config.customs_dir, repo.name.replace("/", os.sep))


def get_override_path(repo):
    return os.path.join(config.override_dir, repo.name.replace("/", os.sep))


def get_override_build_script_path(repo):
    return os.path.join(get_override_path(repo), config.build_scripts[0])


def read_override_build_script(repo):
    build_script_path = get_override_build_script_path(repo)
    if os.path.isfile(build_script_path):
        build_script_file = open(build_script_path, mode="r")
        build_script = build_script_file.read()
        build_script_file.close()
        return build_script
    return ""


def write_override_build_script(repo, build_script):
    build_script_path = get_override_build_script_path(repo)
    if build_script.strip() == "":
        if os.path.isfile(build_script_path):
            os.remove(build_script_path)
    else:
        makedirs(os.path.dirname(build_script_path))
        build_script_file = open(build_script_path, mode="w")
        build_script_file.write(build_script.replace("\r", ""))
        build_script_file.close()


def get_public_key():
    """
  Returns the servers SSH public key.
  """

    # XXX Support all valid options and eventually parse the config file?
    filename = config.ssh_identity_file or os.path.expanduser("~/.ssh/id_rsa")
    if not filename.endswith(".pub"):
        filename += ".pub"
    if os.path.isfile(filename):
        with open(filename) as fp:
            return fp.read()
    return None


def generate_ssh_keypair(public_key_comment):
    """
  Generates new RSA ssh keypair.

  Return:
  tuple(str, str): generated private and public keys
  """

    key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=4096
    )
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_key = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        .decode("ascii")
    )

    if public_key_comment:
        public_key += " " + public_key_comment

    return private_key, public_key


def get_repo_private_key_path(repo):
    """
  Returns path of private key for repository from Customs folder.

  Return:
  str: path to custom private SSH key
  """

    return os.path.join(get_customs_path(repo), "id_rsa")


def get_repo_public_key_path(repo):
    """
  Returns path of public key for repository from Customs folder.

  Return:
  str: path to custom public SSH key
  """

    return os.path.join(get_customs_path(repo), "id_rsa.pub")
