#pragma once

#include <exception>
#include <string>

#include "emulator/CxbxEmbed.h"
#include "Logging.h"

// Internal bridge used by code that historically wrote to a console or
// terminated the desktop process. It is deliberately process-wide: the Cxbx
// core is currently singleton-based and cannot run two Xbox machines at once.
void CxbxEmbedRuntimeActivate(const CxbxEmbedCallbacks& callbacks);
void CxbxEmbedRuntimeDeactivate();
bool CxbxEmbedRuntimeIsActive();
bool CxbxEmbedRuntimeStopRequested();
void CxbxEmbedRuntimeRequestStop();
void CxbxEmbedRuntimeSetD3D11Presentation(const CxbxEmbedD3D11Presentation& presentation);
const CxbxEmbedD3D11Presentation* CxbxEmbedRuntimeGetD3D11Presentation();
void CxbxEmbedRuntimeReportLog(CXBXR_MODULE module, LOG_LEVEL level, const char* message);
void CxbxEmbedRuntimeReportError(CxbxEmbedResult result, const char* message);
CxbxEmbedPromptResult CxbxEmbedRuntimePrompt(
	CxbxEmbedPromptIcon icon, CxbxEmbedPromptButtons buttons,
	CxbxEmbedPromptResult default_result, const char* message);
void CxbxEmbedRuntimeReportHostEvent(CxbxEmbedHostEvent event, uint64_t value);

class CxbxEmbeddedAbort final : public std::exception
{
public:
	explicit CxbxEmbeddedAbort(const char* message) : m_message(message ? message : "Cxbx fatal error") {}
	const char* what() const noexcept override { return m_message.c_str(); }

private:
	std::string m_message;
};
