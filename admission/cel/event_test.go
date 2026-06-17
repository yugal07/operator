package cel

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// newTestAttributes builds an admission.Attributes suitable for tests.
func newTestAttributes(kind, name, namespace, operation, subresource string, obj map[string]interface{}) admission.Attributes {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: kind}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	var u *unstructured.Unstructured
	if obj != nil {
		u = &unstructured.Unstructured{Object: obj}
	}
	userInfo := &user.DefaultInfo{
		Name:   "test-user",
		Groups: []string{"system:masters"},
		UID:    "uid-123",
	}
	return admission.NewAttributesRecord(u, nil, gvk, namespace, name, gvr, subresource,
		admission.Operation(operation), nil, false, userInfo)
}

func TestNewAdmissionCelEvent_AllFields(t *testing.T) {
	obj := map[string]interface{}{
		"command":   []interface{}{"/bin/sh"},
		"container": "main",
	}
	attrs := newTestAttributes("PodExecOptions", "my-pod", "default", "CONNECT", "exec", obj)
	event := NewAdmissionCelEvent(attrs)

	if event.Kind != "PodExecOptions" {
		t.Errorf("Kind = %q, want %q", event.Kind, "PodExecOptions")
	}
	if event.Group != "" {
		t.Errorf("Group = %q, want empty", event.Group)
	}
	if event.Version != "v1" {
		t.Errorf("Version = %q, want %q", event.Version, "v1")
	}
	if event.Name != "my-pod" {
		t.Errorf("Name = %q, want %q", event.Name, "my-pod")
	}
	if event.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q", event.Namespace, "default")
	}
	if event.Operation != "CONNECT" {
		t.Errorf("Operation = %q, want %q", event.Operation, "CONNECT")
	}
	if event.Subresource != "exec" {
		t.Errorf("Subresource = %q, want %q", event.Subresource, "exec")
	}
	if event.Resource != "pods" {
		t.Errorf("Resource = %q, want %q", event.Resource, "pods")
	}
	if event.DryRun {
		t.Error("DryRun = true, want false")
	}

	// UserInfo
	if event.UserInfo.Username != "test-user" {
		t.Errorf("UserInfo.Username = %q, want %q", event.UserInfo.Username, "test-user")
	}
	if len(event.UserInfo.Groups) != 1 || event.UserInfo.Groups[0] != "system:masters" {
		t.Errorf("UserInfo.Groups = %v, want [system:masters]", event.UserInfo.Groups)
	}
	if event.UserInfo.UID != "uid-123" {
		t.Errorf("UserInfo.UID = %q, want %q", event.UserInfo.UID, "uid-123")
	}

	// Object
	if event.Object == nil {
		t.Fatal("Object is nil, want non-nil")
	}
	if event.Object["container"] != "main" {
		t.Errorf("Object[container] = %v, want %q", event.Object["container"], "main")
	}
}

func TestNewAdmissionCelEvent_NilOldObject(t *testing.T) {
	attrs := newTestAttributes("Pod", "test-pod", "kube-system", "CREATE", "", map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
	})
	event := NewAdmissionCelEvent(attrs)

	if event.OldObject != nil {
		t.Errorf("OldObject = %v, want nil", event.OldObject)
	}
}

func TestNewAdmissionCelEvent_NilObject(t *testing.T) {
	// Build attributes with no object at all.
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	userInfo := &user.DefaultInfo{Name: "anon"}
	attrs := admission.NewAttributesRecord(nil, nil, gvk, "default", "test", gvr, "",
		admission.Operation("DELETE"), nil, false, userInfo)

	event := NewAdmissionCelEvent(attrs)

	if event.Object != nil {
		t.Errorf("Object = %v, want nil", event.Object)
	}
	if event.OldObject != nil {
		t.Errorf("OldObject = %v, want nil", event.OldObject)
	}
}

func TestNewAdmissionCelEvent_WithOldObject(t *testing.T) {
	oldObj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "old-pod"},
	}
	newObj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "new-pod"},
	}

	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	uNew := &unstructured.Unstructured{Object: newObj}
	uOld := &unstructured.Unstructured{Object: oldObj}
	userInfo := &user.DefaultInfo{Name: "admin"}

	attrs := admission.NewAttributesRecord(uNew, uOld, gvk, "default", "my-pod", gvr, "",
		admission.Operation("UPDATE"), nil, false, userInfo)

	event := NewAdmissionCelEvent(attrs)

	if event.OldObject == nil {
		t.Fatal("OldObject is nil, want non-nil")
	}
	meta, ok := event.OldObject["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("OldObject[metadata] is not a map")
	}
	if meta["name"] != "old-pod" {
		t.Errorf("OldObject.metadata.name = %v, want %q", meta["name"], "old-pod")
	}
}
