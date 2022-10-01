package kz.ncanode.dto.response;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class XmlSignResponse extends StatusResponse {
    private String xml;
}
