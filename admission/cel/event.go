package cel

import (
	"k8s.io/apiserver/pkg/admission"
)

// AdmissionCelUserInfo holds user identity fields extracted from an admission
// request. Exported fields are registered with the CEL type system so
// expressions can reference e.g. event.UserInfo.Username.
type AdmissionCelUserInfo struct {
	Username string
	Groups   []string
	UID      string
}

// AdmissionCelEvent is a plain Go struct that mirrors the interesting fields
// of admission.Attributes. It is registered with cel-go's native type system
// so CEL expressions can access fields like event.kind, event.namespace, etc.
type AdmissionCelEvent struct {
	Kind        string
	Group       string
	Version     string
	Name        string
	Namespace   string
	Operation   string
	Subresource string
	Resource    string
	DryRun      bool
	UserInfo    AdmissionCelUserInfo
	Object      map[string]interface{}
	OldObject   map[string]interface{}
	Options     map[string]interface{}
}

// unstructuredContent is the interface implemented by *unstructured.Unstructured.
type unstructuredContent interface {
	UnstructuredContent() map[string]interface{}
}

// NewAdmissionCelEvent extracts all relevant fields from admission.Attributes
// into an AdmissionCelEvent suitable for CEL evaluation.
func NewAdmissionCelEvent(attrs admission.Attributes) *AdmissionCelEvent {
	event := &AdmissionCelEvent{
		Kind:        attrs.GetKind().Kind,
		Group:       attrs.GetKind().Group,
		Version:     attrs.GetKind().Version,
		Name:        attrs.GetName(),
		Namespace:   attrs.GetNamespace(),
		Operation:   string(attrs.GetOperation()),
		Subresource: attrs.GetSubresource(),
		Resource:    attrs.GetResource().Resource,
		DryRun:      attrs.IsDryRun(),
	}

	// Extract user info.
	if ui := attrs.GetUserInfo(); ui != nil {
		event.UserInfo = AdmissionCelUserInfo{
			Username: ui.GetName(),
			Groups:   ui.GetGroups(),
			UID:      ui.GetUID(),
		}
	}

	// Extract Object content.
	if obj := attrs.GetObject(); obj != nil {
		if u, ok := obj.(unstructuredContent); ok {
			event.Object = u.UnstructuredContent()
		}
	}

	// Extract OldObject content (populated for UPDATE and DELETE).
	if old := attrs.GetOldObject(); old != nil {
		if u, ok := old.(unstructuredContent); ok {
			event.OldObject = u.UnstructuredContent()
		}
	}

	// Options mirrors Object — useful for subresource events (exec, portforward)
	// where the "object" is really the options struct.
	if opts := attrs.GetOperationOptions(); opts != nil {
		if u, ok := opts.(unstructuredContent); ok {
			event.Options = u.UnstructuredContent()
		}
	}

	return event
}
