@load ./file-extensions

module FileExtraction;

export {
	const path: string = "" &redef;

    const bad_extensions: set[string] = {
        "x-cross-domain-policy",
        "x-debian-package",
        "chrome-ext-upd",
        "x-hx-aac-adts",
        "ocsp-response",
        "ocsp-request",
        "font-woff2",
        "soap+xml",
        "svg+xml",
        "html",
        "json",
        "mp2t",
        "cab",
        "xml",
        "png",
        "jpg",
        "gif",
        "txt"
    } &redef;

	global extract: hook(f: fa_file, meta: fa_metadata);
	global ignore: hook(f: fa_file, meta: fa_metadata);
}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( meta?$mime_type && !hook FileExtraction::extract(f, meta) )
		{
            if ( !hook FileExtraction::ignore(f, meta) )
                return;
            if ( meta$mime_type in mime_to_ext )
                local fext = mime_to_ext[meta$mime_type];
            else
                fext = split_string(meta$mime_type, /\//)[1];

            if (f$source == "HTTP")
                {
                if (fext in bad_extensions == F)
                    {
                    local filename = fmt("%s%s-%s.%s", path, f$source, f$id, fext);
                    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=filename]);
                    }
                }
        }
    }
