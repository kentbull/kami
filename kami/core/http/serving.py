import mimetypes
import os
import sys

import falcon


class StaticSink:
    """
    Class that provides Falcon sink endpoint for serving static files in support
    of a client side web app.

    """
    StaticSinkBasePath = "/static"
    DefaultStaticSinkBasePath = "/"

    def __init__(self, staticDirPath=None):
        """
        Parameters:
           staticDirPath (str): path to static sink directory

        Example computation of staticDirPath:

        WEB_DIR_PATH = os.path.dirname(
                            os.path.abspath(
                                sys.modules.get(__name__).__file__))
        STATIC_DIR_PATH = os.path.join(WEB_DIR_PATH, 'static')

        /Users/Load/Data/Code/public/hio/src/hio/demo/web/static
        """
        if staticDirPath is None:
            staticDirPath == os.path.join(
                os.path.dirname(
                    os.path.abspath(
                        sys.modules.get(__name__).__file__)),
                self.StaticSinkBasePath[1:])
        self.staticDirPath = staticDirPath

    def __call__(self, req, rep):
        path = req.path.removeprefix(self.StaticSinkBasePath)
        path = path.removeprefix(self.DefaultStaticSinkBasePath)
        if not path:  # return default
            path = "index.html"
        path = os.path.join(self.staticDirPath, path)
        if not os.path.exists(path):
            raise falcon.HTTPError(falcon.HTTP_NOT_FOUND,
                                   title='Missing Resource',
                                   description='File "{}" not found or forbidden'.format(path))
        filetype = mimetypes.guess_type(path, strict=True)[0]  # get first guess
        rep.set_header("Content-Type", "{}; charset=UTF-8".format(filetype))
        rep.status = falcon.HTTP_200  # This is the default status
        # for better stream handling provide "wsgi.file_wrapper" in wsgi environ
        # rep.stream = open(filepath, 'rb')
        # the following works faster and more consistently than rep.stream above
        # Maybe Falcon's default is to throttle the reads too much for rep.stream
        with open(path, 'rb') as f:
            rep.data = f.read()