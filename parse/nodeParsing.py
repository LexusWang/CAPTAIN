from parse.cdm18.trace_parser import parse_subject_trace, parse_object_trace
from parse.cdm18.cadets_parser import parse_subject_cadets, parse_object_cadets
from parse.cdm18.fivedirections_parser import parse_subject_fivedirections, parse_object_fivedirections
import pdb

def parse_subject(self, datum, format, cdm_version):
    if format in {'cadets'}:
        return parse_subject_cadets(self, datum, cdm_version)
    elif format in {'fivedirections'}:
        return parse_subject_fivedirections(self, datum, cdm_version)
    elif format in {'trace'}:
        return parse_subject_trace(self, datum, cdm_version)

def parse_object(self, datum, object_type, format, cdm_version):
    if format in {'trace'}:
        object = parse_object_trace(self, datum, object_type)
    elif format in {'cadets'}:
        object = parse_object_cadets(self, datum, object_type)
    elif format in {'fivedirections'}:
        object = parse_object_fivedirections(self, datum, object_type)
    return object