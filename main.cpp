/*
 *  _ .-') _     ('-.              ('-.     _   .-')   .-. .-')    ('-.  _  .-')   .-') _    
 * ( (  OO) )  _(  OO)            ( OO ).-.( '.( OO )_ \  ( OO ) _(  OO)( \( -O ) (  OO) )   
 *  \     .'_ (,------.,--.       / . --. / ,--.   ,--.);-----.\(,------.,------. /     '._  
 * ,`'--..._) |  .---'|  |.-')   | \-.  \  |   `.'   | | .-.  | |  .---'|   /`. '|'--...__) 
 * |  |  \  ' |  |    |  | OO ).-'-'  |  | |         | | '-' /_)|  |    |  /  | |'--.  .--' 
 * |  |   ' |(|  '--. |  |`-' | \| |_.'  | |  |'.'|  | | .-. `.(|  '--. |  |_.' |   |  |    
 * |  |   / : |  .--'(|  '---.'  |  .-.  | |  |   |  | | |  \  ||  .--' |  .  '.'   |  |    
 * |  '--'  / |  `---.|      |   |  | |  | |  |   |  | | '--'  /|  `---.|  |\  \    |  |    
 * `-------'  `------'`------'   `--' `--' `--'   `--' `------' `------'`--' '--'   `--'    
 * DeLambert
 *
 * An IDA plugin to deobfuscate strings from The Lamberts macOS malware sample
 * af7c395426649c57e44eac0bb6c6a109ac649763065ff5b2b23db71839bac655
 *
 * 24/08/2021
 * Pedro Vilaça - reverser@put.as - https://reverse.put.as
 *
 * Public domain code, do whatever you want, just give credits if you any of this :P
 *
 * Greets to:
 * - CIA: can I haz a mug? Those wiki entries are enough, no?
 * - NSA: love your malicious code and engineering. ETA next leak?
 *
 * Fucks to:
 * - The Cupertino clowns: keep the lulz coming!
 *
 */

#include <set>
#include <loader.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <intel.hpp>
#include <search.hpp>
#include <gdl.hpp>
#include <auto.hpp>
#include <intel.hpp>
#include <stdint.h>
#include <segment.hpp>

#define VERSION "1.0"

#define DEBUG_MSG(fmt, ...) msg("[DEBUG] " fmt "\n", ## __VA_ARGS__)
#define ERROR_MSG(fmt, ...) msg("[ERROR] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) msg(fmt " \n", ## __VA_ARGS__)

extern plugin_t PLUGIN;

//---------------------------------------------------------------------------
// The deobfuscation code
// Straight out of HexRays with small tweaks - lazyness++
// Geoff Chappell is right about people's F5 lazyness but not worth the effort on this one
char * deobfuscate_string(char *input_buf, char *output_buf, int a3)
{
	char *v3; // ecx
	char *j; // edx
	char *v5; // esi
	char xorkey2; // di
	char xorsum; // bl
	unsigned int v8; // eax
	char *v9; // edx
	char *v11; // [esp+8h] [ebp-28h]
	int v12; // [esp+10h] [ebp-20h]
	char *v14; // [esp+18h] [ebp-18h]
	int input_len; // [esp+1Ch] [ebp-14h]
	int i; // [esp+20h] [ebp-10h]

	v14 = input_buf;
	v12 = a3;
	if ( *(char *)input_buf <= 8 )
	{
		input_len = *(uint8_t *)(input_buf + 1) + ((*(char *)input_buf & 0xF) << 8);
		v5 = (char *)(input_buf + 4);
		xorkey2 = *(char *)(input_buf + 3);
		xorsum = xorkey2 + *(char *)(input_buf + 2);
		for ( i = 0; ; ++i )
		{
			xorsum += xorkey2;
			v8 = input_len;
			if ( i == input_len )
				break;
			v11 = &output_buf[i];
			*v11 = (xorsum - xorkey2) ^ *v5++;
		}
		v9 = &output_buf[input_len];
		while ( v8 < input_len + a3 )
		{
			*v9 = 0;
			++v8;
			++v9;
		}
		return output_buf;
	}
	if ( !memcmp("", (const char *)input_buf, 4) )
	{
		v3 = output_buf;
		for ( j = (char *)(v14 + 4); *j != 127; ++j )
			*v3++ = *j;
		while ( --v12 != -1 )
			*v3++ = 0;
		return output_buf;
	}
	return (char *)v14;
}

ea_t find_base(ea_t start, ea_t end, uint16_t reg) {
	ea_t cur = start;
	ea_t found_call = 0;
	while (cur < end) {
		insn_t ins;
		int size = decode_insn(&ins, cur);
		if (size == 0) {
			ERROR_MSG("Bad instruction at 0x%x", cur);
			return 0;
		}
		if (ins.itype == NN_call) {
			found_call = ins.ea;
		}
		if (ins.itype == NN_pop && 
			ins.Op1.type == o_reg && 
			ins.Op1.reg == reg &&
			ins.ea == found_call + 5) 
		{
			DEBUG_MSG("Found POP at 0x%x", ins.ea);
			return ins.ea;
		}
		cur += size;
	}
	return 0;
}

bool start_deobfuscation(ea_t src) {
	segment_t *seg = getseg(src);
	if (seg == NULL) {
		ERROR_MSG("Failed to retrieve segment information.");
		return false;
	}

	qstring segname;
	if (get_segm_name(&segname, seg, 0) < 0) {
		ERROR_MSG("Failed to retrieve segment name.");
		return false;
	}

	ea_t target_addr = 0;
	
	// if it's in the code segment we need to find the source buffer
	if (strcmp(segname.c_str(), "__text") == 0) {
		insn_t ins;
		int size = decode_insn(&ins, src);
		if (size == 0) {
			ERROR_MSG("Bad instruction at 0x%x", src);
			return false;
		}
		if (ins.itype != NN_lea) {
			ERROR_MSG("Target instruction not a LEA at 0x%x.", src);
			return false;
		}

		func_t *function = get_func(src);
		rangeset_t range;
		if (get_func_ranges(&range, function) == BADADDR) {
			ERROR_MSG("Invalid function range returned.");
			return false;
		}
		range_t a = range.getrange(0);
		// r_phrase contains the base register
		ea_t base = find_base(a.start_ea, a.end_ea, ins.Op2.phrase);
		if (base == 0) {
			ERROR_MSG("Failed to find base register address.");
			return false;
		}
		target_addr = ins.Op2.addr + base;
	} 
	// else assume it's on cstring :-]
	else {
		target_addr = src;
	}

	// most start with 0 but code says is valid if <= 8
	uint64_t start_value = get_original_byte(target_addr);
	if (start_value != 0) {
		ERROR_MSG("Bad starting value.");
		return false;
	}

	struct header {
		uint8_t magic;
		uint8_t len;
		uint8_t xorkey1;
		uint8_t xorkey2;
	} header;

	if (get_bytes(&header, sizeof(struct header), target_addr) <= 0) {
		ERROR_MSG("Failed to retrieve bytes");
		return false;
	}

	size_t encrypted_buf_len = header.len + sizeof(struct header);
	char *encrypted_buf = (char*)qalloc(encrypted_buf_len);
	if (encrypted_buf == NULL) {
		ERROR_MSG("Failed to allocate memory.");
		return false;
	}

	if (get_bytes(encrypted_buf, encrypted_buf_len, target_addr) <= 0) {
		ERROR_MSG("Failed to read encrypted bytes.");
		qfree(encrypted_buf);
		encrypted_buf = NULL;
		return false;
	}

	char decrypted_buf[2048] = {0};
	deobfuscate_string(encrypted_buf, decrypted_buf, 1);
	DEBUG_MSG("Deobfuscated: %s", decrypted_buf);

	char tag_string[128] = {0};
	qsnprintf(tag_string, sizeof(tag_string), "%s", decrypted_buf);
	set_cmt(src, tag_string, false);
	qfree(encrypted_buf);
	encrypted_buf = NULL;
}

//---------------------------------------------------------------------------
// Action handlers

/*
 * the action handlers responsible for doing something
 * when we select the menu options
 */
struct dl_ctx_t;

struct deobfuscate_ah_t : public action_handler_t
{
	dl_ctx_t &p;
	deobfuscate_ah_t(dl_ctx_t &c) : p(c) {}
	virtual int idaapi activate(action_activation_ctx_t *ctx) override {
		ea_t src = get_screen_ea();
		if (src != BADADDR) {
			start_deobfuscation(src);
		}
		return true;
	}
	virtual action_state_t idaapi update(action_update_ctx_t *ctx) override {
		return AST_ENABLE;
	}
};

#define DEOBFUSCATE_ACTION_NAME		"dl:Deobfuscate"

struct dl_ctx_t : public plugmod_t
{
	bool hooked = false;

	deobfuscate_ah_t deobfuscate_ah = deobfuscate_ah_t(*this);
	const action_desc_t deobfuscate_action = ACTION_DESC_LITERAL_PLUGMOD(
		DEOBFUSCATE_ACTION_NAME,
		"Deobfuscate Lamberts string",
		&deobfuscate_ah,
		this,
		NULL,
		"Deobfuscate Lamberts string",
		-1);

	dl_ctx_t();
	~dl_ctx_t();
	
	virtual bool idaapi run(size_t arg) override;
};

//---------------------------------------------------------------------------
// Callback for ui notifications
static ssize_t idaapi ui_callback(void *ud, int notification_code, va_list va)
{
	switch (notification_code)
	{
		// called when IDA is preparing a context menu for a view
		// Here dynamic context-depending user menu items can be added.
		case ui_finish_populating_widget_popup:
		{
			TWidget *view = va_arg(va, TWidget *);
			// BWN_DISASM is for disassembly view
			// check include/kernwin.hpp for available window types
			// add to disassembler view context menu
			if ( get_widget_type(view) == BWN_DISASM )
			{
				TPopupMenu *p = va_arg(va, TPopupMenu *);
				// attach all our menu actions
				attach_action_to_popup(view, p, DEOBFUSCATE_ACTION_NAME);
			}
			break;
		}
	}
	return 0; 	// 0 means "continue processing the event"
				// otherwise the event is considered as processed
}

//--------------------------------------------------------------------------
plugmod_t * idaapi init(void)
{
	if (is_idaq() == false) {
		return nullptr;
	}

	msg("--------------------------------------------\n");
	msg("DeLambert %s build %d\n", VERSION, __BUILD_NUMBER);
	msg("--------------------------------------------\n");

	return new dl_ctx_t;
}

//--------------------------------------------------------------------------
dl_ctx_t::dl_ctx_t() 
{
	DEBUG_MSG("New DeLambert plugin instance");
	// we need to register each action and then attach to a menu item in the callback
	// the moment we register the items are available via shortcut if it exists
	register_action(deobfuscate_action);
	/* set callback for view notifications */
	if (!hooked) {
		hook_to_notification_point(HT_UI, ui_callback, this);
		hooked = true;
	}
}

dl_ctx_t::~dl_ctx_t()
{
	if (hooked) {
		unhook_from_notification_point(HT_UI, ui_callback, this);
		unregister_action(DEOBFUSCATE_ACTION_NAME);
	}
	msg("---------------------------\n");
	msg("Unloaded DeLambert\n");
	msg("---------------------------\n");
}

//--------------------------------------------------------------------------
bool idaapi dl_ctx_t::run(size_t)
{    
	DEBUG_MSG("DeLambert v%s ready to rock'n'roll!", VERSION);
	return true;
}

//--------------------------------------------------------------------------
static const char comment[] = "DeLambert";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,  				// plugin flags
	init,						// initialize
	nullptr,					// terminate. this pointer may be NULL.
	nullptr,					// invoke plugin
	comment,					// long comment about the plugin
								// it could appear in the status line
								// or as a hint
	"Lambert strings deobfuscator",	// multiline help about the plugin
	"DeLambert",				// the preferred short name of the plugin
	""							// the preferred hotkey to run the plugin
};
