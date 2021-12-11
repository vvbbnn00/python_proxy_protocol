class BaseHTTPRequestHandler(socketserver.StreamRequestHandler):
    """HTTP request handler base class.

    The following explanation of HTTP serves to guide you through the
    code as well as to expose any misunderstandings I may have about
    HTTP (so you don't need to read the code to figure out I'm wrong
    :-).

    Modified by vvbbnn00, who have made it supports proxy protocol v1 & v2.
    - Bzpl_Proxy/0.1.0  2021/12/12 00:05:00

    HTTP (HyperText Transfer Protocol) is an extensible protocol on
    top of a reliable stream transport (e.g. TCP/IP).  The protocol
    recognizes three parts to a request:

    1. One line identifying the request type and path
    2. An optional set of RFC-822-style headers
    3. An optional data part

    The headers and data are separated by a blank line.

    The first line of the request has the form

    <command> <path> <version>

    where <command> is a (case-sensitive) keyword such as GET or POST,
    <path> is a string containing path information for the request,
    and <version> should be the string "HTTP/1.0" or "HTTP/1.1".
    <path> is encoded using the URL encoding scheme (using %xx to signify
    the ASCII character with hex code xx).

    The specification specifies that lines are separated by CRLF but
    for compatibility with the widest range of clients recommends
    servers also handle LF.  Similarly, whitespace in the request line
    is treated sensibly (allowing multiple spaces between components
    and allowing trailing whitespace).

    Similarly, for output, lines ought to be separated by CRLF pairs
    but most clients grok LF characters just fine.

    If the first line of the request has the form

    <command> <path>

    (i.e. <version> is left out) then this is assumed to be an HTTP
    0.9 request; this form has no optional headers and data part and
    the reply consists of just the data.

    The reply form of the HTTP 1.x protocol again has three parts:

    1. One line giving the response code
    2. An optional set of RFC-822-style headers
    3. The data

    Again, the headers and data are separated by a blank line.

    The response code line has the form

    <version> <responsecode> <responsestring>

    where <version> is the protocol version ("HTTP/1.0" or "HTTP/1.1"),
    <responsecode> is a 3-digit response code indicating success or
    failure of the request, and <responsestring> is an optional
    human-readable string explaining what the response code means.

    This server parses the request and the headers, and then calls a
    function specific to the request type (<command>).  Specifically,
    a request SPAM will be handled by a method do_SPAM().  If no
    such method exists the server sends an error response to the
    client.  If it exists, it is called with no arguments:

    do_SPAM()

    Note that the request name is case sensitive (i.e. SPAM and spam
    are different requests).

    The various request details are stored in instance variables:

    - client_address is the client IP address in the form (host,
    port);

    - command, path and version are the broken-down request line;

    - headers is an instance of email.message.Message (or a derived
    class) containing the header information;

    - rfile is a file object open for reading positioned at the
    start of the optional input data part;

    - wfile is a file object open for writing.

    IT IS IMPORTANT TO ADHERE TO THE PROTOCOL FOR WRITING!

    The first thing to be written must be the response line.  Then
    follow 0 or more header lines, then a blank line, and then the
    actual data (if any).  The meaning of the header lines depends on
    the command executed by the server; in most cases, when data is
    returned, there should be at least one header line of the form

    Content-type: <type>/<subtype>

    where <type> and <subtype> should be registered MIME types,
    e.g. "text/html" or "text/plain".

    """

    # The Python system version, truncated to its first component.
    sys_version = "Python/" + sys.version.split()[0]

    # The server software version.  You may want to override this.
    # The format is multiple whitespace-separated strings,
    # where each string is of the form name[/version].
    server_version = "BaseHTTP/" + __version__

    error_message_format = DEFAULT_ERROR_MESSAGE
    error_content_type = DEFAULT_ERROR_CONTENT_TYPE

    # The default request version.  This only affects responses up until
    # the point where the request line is parsed, so it mainly decides what
    # the client gets back when sending a malformed request line.
    # Most web servers default to HTTP 0.9, i.e. don't send a status line.
    default_request_version = "HTTP/0.9"

    request_start = True
    enable_proxy_protocol_v2 = False
    proxy_info = []

    def parse_request(self):
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, any relevant
        error response has already been sent back.

        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')

        # --Proxy Protocol V2--

        if self.request_start:  # First time read the stream
            self.request_start = False
            if self.raw_requestline == b"\r\n":
                # Judge if is proxy_protocol_v2, its signature should be b'\r\n\r\n\x00\r\nQUIT\n'
                if self.rfile.readline(65537) != b"\r\n":
                    return False
                if self.rfile.readline(65537) != b"\x00\r\n":
                    return False
                if self.rfile.readline(65537) != b"QUIT\n":
                    return False
                self.enable_proxy_protocol_v2 = True

        # print("enable_proxy_protocol_v2", self.enable_proxy_protocol_v2)

        if self.enable_proxy_protocol_v2:  # If protocol proxy v2
            requestline = self.rfile.readline(65537)  # Read next line
            # The first 4 Bytes should be the data of IP address
            proxy_info = requestline[0:4]  # Proxy info
            # print(proxy_info)
            # The next byte (the 13th one) is the protocol version and command.
            # The highest four bits contains the version. As of this specification, it must
            # always be sent as \x2 and the receiver must only accept this value.
            proxy_protocol_version_command = proxy_info[0]
            proxy_protocol_version = proxy_protocol_version_command >> 4
            # print('Version:', proxy_protocol_version)
            # The lowest four bits represents the command.
            # \x0-LOCAL \x1-PROXY Other-Drop
            proxy_protocol_command = proxy_protocol_version_command - (proxy_protocol_version << 4)
            # print('Command:', proxy_protocol_command)
            if proxy_protocol_command != 0 and proxy_protocol_command != 1:
                return False

            # The 14th byte contains the transport protocol and address family. The highest 4
            # bits contain the address family, the lowest 4 bits contain the protocol.
            proxy_protocol_address = proxy_info[1]
            proxy_protocol_address_family = proxy_protocol_address >> 4
            # print('Address Family:', proxy_protocol_address_family)
            # 0x1-IPv4 0x2-IPv6
            # Other-Drop because http servers only accept AF_INET/AF_INET6
            if proxy_protocol_address_family != 1 and proxy_protocol_address_family != 2:
                return False
            # The transport protocol is specified in the lowest 4 bits of the 14th byte
            # 0x1-TCP
            # Other-Drop because http servers only accept TCP traffic
            proxy_protocol_address_protocol = proxy_protocol_address - (proxy_protocol_address_family << 4)
            if proxy_protocol_address_protocol != 1:
                return False
            # print('Address Protocol:', proxy_protocol_address_family)

            # The 15th and 16th bytes is the address length in bytes in network endian order.
            proxy_protocol_ip_data_length = (proxy_info[2] << 4) + int(proxy_info[3])
            # print('IP Data Length:', proxy_protocol_ip_data_length)

            # Starting from the 17th byte, addresses are presented in network byte order.
            # The address order is always the same :
            #   - source layer 3 address in network byte order
            #   - destination layer 3 address in network byte order
            #   - source layer 4 address if any, in network byte order (port)
            #   - destination layer 4 address if any, in network byte order (port)

            proxy_protocol_ip_data = requestline[4:proxy_protocol_ip_data_length + 4]
            # print('IP Data Raw:', proxy_protocol_ip_data)
            self.proxy_info = []
            if proxy_protocol_address_family == 1:  # TCP4
                self.proxy_info.append('TCP4')
                proxy_protocol_src_ip = proxy_protocol_ip_data[0:4]
                self.proxy_info.append('%r.%r.%r.%r' %
                                       (proxy_protocol_src_ip[0], proxy_protocol_src_ip[1], proxy_protocol_src_ip[2],
                                        proxy_protocol_src_ip[3]))
                proxy_protocol_dist_ip = proxy_protocol_ip_data[4:8]
                self.proxy_info.append('%r.%r.%r.%r' %
                                       (proxy_protocol_dist_ip[0], proxy_protocol_dist_ip[1], proxy_protocol_dist_ip[2],
                                        proxy_protocol_dist_ip[3]))
                self.proxy_info.append((proxy_protocol_ip_data[8] << 8) + proxy_protocol_ip_data[9])
                self.proxy_info.append((proxy_protocol_ip_data[10] << 8) + proxy_protocol_ip_data[11])
            else:
                self.proxy_info.append('TCP6')

                def bytes_2_ip6(bytes_arr):
                    ip_int = int.from_bytes(bytes_arr, byteorder='big')
                    import ipaddress
                    return str(ipaddress.ip_address(ip_int))

                proxy_protocol_src_ip = proxy_protocol_ip_data[0:16]
                self.proxy_info.append(bytes_2_ip6(proxy_protocol_src_ip))
                proxy_protocol_dist_ip = proxy_protocol_ip_data[16:32]
                self.proxy_info.append(bytes_2_ip6(proxy_protocol_dist_ip))
                self.proxy_info.append((proxy_protocol_ip_data[32] << 8) + proxy_protocol_ip_data[33])
                self.proxy_info.append((proxy_protocol_ip_data[34] << 8) + proxy_protocol_ip_data[35])

            # print(self.proxy_info)
            requestline = str(requestline[4 + proxy_protocol_ip_data_length:], 'iso-8859-1')  # Real request data
        # ------------------

        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline

        # --Proxy Protocol V1--
        words = requestline.split()

        if len(words) == 0:
            return False

        if words[0] == "PROXY":  # If run with proxy_protocol v1
            try:
                self.proxy_info = [words[1], words[2], words[3], words[4], words[5]]
                # Proxy info: [AF, L3_SADDR, L3_DADDR, L4_SADDR, L4_DADDR]
            except:
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad Protocol Data")
                return False
            self.handle_one_request()  # Read next line
            requestline = str(self.raw_requestline, 'iso-8859-1')
            requestline = re.sub("^PROXY[ a-z0-9A-Z.]*\r\n", "",
                                 requestline)  # Delete proxy line to make sure the request is valid
            requestline = requestline.rstrip('\r\n')
            self.requestline = requestline
            words = requestline.split()  # Regenerate the words
        # ------------------

        if len(words) == 0:
            return False

        if len(words) >= 3:  # Enough to determine protocol version
            version = words[-1]
            try:
                if not version.startswith('HTTP/'):
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
            self.request_version = version

        if not 2 <= len(words) <= 3:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % requestline)
            return False
        command, path = words[:2]
        if len(words) == 2:
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % command)
                return False
        self.command, self.path = command, path

        # Examine the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(self.rfile,
                                                     _class=self.MessageClass)

            # If Proxy, automatically add headers
            if self.proxy_info != []:
                # print("Through Proxy", requestline, self.proxy_info)
                self.headers.add_header('X-Real-IP', self.proxy_info[1])
                if self.headers.get('X-Forwarded-For'):
                    self.headers.add_header('X-Forwarded-For',
                                            self.headers.get('X-Forwarded-For') + ',' + self.proxy_info[1])
                else:
                    self.headers.add_header('X-Forwarded-For', self.proxy_info[1])
            # ---------

        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def handle_expect_100(self):
        """Decide what to do with an "Expect: 100-continue" header.

        If the client is expecting a 100 Continue response, we must
        respond with either a 100 Continue or a final response before
        waiting for the request body. The default is to always respond
        with a 100 Continue. You can behave differently (for example,
        reject unauthorized requests) by overriding this method.

        This method should either return True (possibly after sending
        a 100 Continue response) or send an error response and return
        False.

        """
        self.send_response_only(HTTPStatus.CONTINUE)
        self.end_headers()
        return True
