struct VsOut
{
    float4 position : SV_Position;
    float2 texcoord : TEXCOORD0;
};

VsOut main(uint vertexId : SV_VertexID)
{
    VsOut output;
    // Oversized fullscreen triangle: no vertex/index buffer or input layout.
    float2 uv = float2((vertexId << 1) & 2, vertexId & 2);
    output.position = float4(uv.x * 2.0f - 1.0f, 1.0f - uv.y * 2.0f, 0.0f, 1.0f);
    output.texcoord = uv;
    return output;
}
