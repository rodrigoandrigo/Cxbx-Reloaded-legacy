Texture2D<float4> GuestFrame : register(t0);
SamplerState GuestSampler : register(s0);

float4 main(float4 position : SV_Position, float2 texcoord : TEXCOORD0) : SV_Target
{
    return GuestFrame.Sample(GuestSampler, texcoord);
}
