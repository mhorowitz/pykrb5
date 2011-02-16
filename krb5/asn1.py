from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful

def _sequence_tag(tag_value):
    return univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, tag_value))

def _sequence_component(name, tag_value, type, **subkwargs):
    return namedtype.NamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

def _sequence_optional_component(name, tag_value, type, **subkwargs):
    return namedtype.OptionalNamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

class Int32(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        -2147483648, 2147483647)

class UInt32(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295)

class KerberosString(char.GeneralString):
    # TODO marc: I'm not sure how to express this constraint in the API.
    # For now, we will be liberal in what we accept.
    # subtypeSpec = constraint.PermittedAlphabetConstraint(char.IA5String())
    pass

class Realm(KerberosString):
    pass

class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("name-type", 0, Int32()),
        _sequence_component("name-string", 1,
                            univ.SequenceOf(componentType=KerberosString()))
                            )

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("etype", 0, Int32()),
        _sequence_optional_component("kvno", 1, UInt32()),
        _sequence_component("cipher", 2, univ.OctetString())
        )


class Ticket(univ.Sequence):
    tagSet = _sequence_tag(1)
    componentType = namedtype.NamedTypes(
        _sequence_component("tkt-vno", 0, univ.Integer(),
                            subtypeSpec=constraint.ValueRangeConstraint(5, 5)),
#        _sequence_component("tkt-vno", 0, univ.Integer().subtypeSpec(
#                            constraint.ValueRangeConstraint(5, 5))),
        _sequence_component("realm", 1, Realm()),
        _sequence_component("sname", 2, PrincipalName()),
        _sequence_component("enc-part", 3, EncryptedData())
        )
