/*
Copyright (c) 2014 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package find

import (
	"errors"
	"path"

	"github.com/vmware/govmomi/list"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"golang.org/x/net/context"
)

type Finder struct {
	client   *vim25.Client
	recurser list.Recurser

	dc      *object.Datacenter
	folders *object.DatacenterFolders
}

func NewFinder(client *vim25.Client, all bool) *Finder {
	f := &Finder{
		client: client,
		recurser: list.Recurser{
			Collector: property.DefaultCollector(client),
			All:       all,
		},
	}

	return f
}

func (f *Finder) SetDatacenter(dc *object.Datacenter) *Finder {
	f.dc = dc
	f.folders = nil
	return f
}

type findRelativeFunc func(ctx context.Context) (object.Reference, error)

func (f *Finder) find(ctx context.Context, fn findRelativeFunc, tl bool, arg string) ([]list.Element, error) {
	root := list.Element{
		Path:   "/",
		Object: object.NewRootFolder(f.client),
	}

	parts := list.ToParts(arg)

	if len(parts) > 0 {
		switch parts[0] {
		case "..": // Not supported; many edge case, little value
			return nil, errors.New("cannot traverse up a tree")
		case ".": // Relative to whatever
			pivot, err := fn(ctx)
			if err != nil {
				return nil, err
			}

			mes, err := mo.Ancestors(ctx, f.client, f.client.ServiceContent.PropertyCollector, pivot.Reference())
			if err != nil {
				return nil, err
			}

			for _, me := range mes {
				// Skip root entity in building inventory path.
				if me.Parent == nil {
					continue
				}
				root.Path = path.Join(root.Path, me.Name)
			}

			root.Object = pivot
			parts = parts[1:]
		}
	}

	f.recurser.TraverseLeafs = tl
	es, err := f.recurser.Recurse(ctx, root, parts)
	if err != nil {
		return nil, err
	}

	return es, nil
}

func (f *Finder) datacenter() (*object.Datacenter, error) {
	if f.dc == nil {
		return nil, errors.New("please specify a datacenter")
	}

	return f.dc, nil
}

func (f *Finder) dcFolders(ctx context.Context) (*object.DatacenterFolders, error) {
	if f.folders != nil {
		return f.folders, nil
	}

	dc, err := f.datacenter()
	if err != nil {
		return nil, err
	}

	folders, err := dc.Folders(ctx)
	if err != nil {
		return nil, err
	}

	f.folders = folders

	return f.folders, nil
}

func (f *Finder) dcReference(_ context.Context) (object.Reference, error) {
	dc, err := f.datacenter()
	if err != nil {
		return nil, err
	}

	return dc, nil
}

func (f *Finder) vmFolder(ctx context.Context) (object.Reference, error) {
	folders, err := f.dcFolders(ctx)
	if err != nil {
		return nil, err
	}

	return folders.VmFolder, nil
}

func (f *Finder) hostFolder(ctx context.Context) (object.Reference, error) {
	folders, err := f.dcFolders(ctx)
	if err != nil {
		return nil, err
	}

	return folders.HostFolder, nil
}

func (f *Finder) datastoreFolder(ctx context.Context) (object.Reference, error) {
	folders, err := f.dcFolders(ctx)
	if err != nil {
		return nil, err
	}

	return folders.DatastoreFolder, nil
}

func (f *Finder) networkFolder(ctx context.Context) (object.Reference, error) {
	folders, err := f.dcFolders(ctx)
	if err != nil {
		return nil, err
	}

	return folders.NetworkFolder, nil
}

func (f *Finder) rootFolder(_ context.Context) (object.Reference, error) {
	return object.NewRootFolder(f.client), nil
}

func (f *Finder) managedObjectList(ctx context.Context, path string, tl bool) ([]list.Element, error) {
	fn := f.rootFolder

	if f.dc != nil {
		fn = f.dcReference
	}

	if len(path) == 0 {
		path = "."
	}

	return f.find(ctx, fn, tl, path)
}

func (f *Finder) ManagedObjectList(ctx context.Context, path string) ([]list.Element, error) {
	return f.managedObjectList(ctx, path, false)
}

func (f *Finder) ManagedObjectListChildren(ctx context.Context, path string) ([]list.Element, error) {
	return f.managedObjectList(ctx, path, true)
}

func (f *Finder) DatacenterList(ctx context.Context, path string) ([]*object.Datacenter, error) {
	return f.DatacenterListRecursive(ctx, path, false)
}

// DatacenterListRecursive allows for recursive calls to DatacenterList
func (f *Finder) DatacenterListRecursive(ctx context.Context, path string, recursive bool) ([]*object.Datacenter, error) {
	es, err := f.find(ctx, f.rootFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var dcs []*object.Datacenter
	for _, e := range es {
		ref := e.Object.Reference()
		if ref.Type == "Datacenter" {
			dcs = append(dcs, object.NewDatacenter(f.client, ref))
		}
	}

	if len(dcs) == 0 {
		return nil, &NotFoundError{"datacenter", path}
	}

	return dcs, nil
}

func (f *Finder) Datacenter(ctx context.Context, path string) (*object.Datacenter, error) {
	dcs, err := f.DatacenterList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(dcs) > 1 {
		return nil, &MultipleFoundError{"datacenter", path}
	}

	return dcs[0], nil
}

func (f *Finder) DefaultDatacenter(ctx context.Context) (*object.Datacenter, error) {
	dc, err := f.Datacenter(ctx, "*")
	if err != nil {
		return nil, toDefaultError(err)
	}

	return dc, nil
}

func (f *Finder) DatastoreList(ctx context.Context, path string) ([]*object.Datastore, error) {
	return f.DatastoreListRecursive(ctx, path, false)
}

// DatastoreListRecursive allows for recursive calls to DatastoreList
func (f *Finder) DatastoreListRecursive(ctx context.Context, path string, recursive bool) ([]*object.Datastore, error) {
	es, err := f.find(ctx, f.datastoreFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var dss []*object.Datastore
	for _, e := range es {
		ref := e.Object.Reference()
		if ref.Type == "Datastore" {
			ds := object.NewDatastore(f.client, ref)
			ds.InventoryPath = e.Path

			dss = append(dss, ds)
		}
	}

	if len(dss) == 0 {
		return nil, &NotFoundError{"datastore", path}
	}

	return dss, nil
}

func (f *Finder) Datastore(ctx context.Context, path string) (*object.Datastore, error) {
	dss, err := f.DatastoreList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(dss) > 1 {
		return nil, &MultipleFoundError{"datastore", path}
	}

	return dss[0], nil
}

func (f *Finder) DefaultDatastore(ctx context.Context) (*object.Datastore, error) {
	ds, err := f.Datastore(ctx, "*")
	if err != nil {
		return nil, toDefaultError(err)
	}

	return ds, nil
}

func (f *Finder) ComputeResourceList(ctx context.Context, path string) ([]*object.ComputeResource, error) {
	return f.ComputeResourceListRecursive(ctx, path, false)
}

// ComputeResourceListRecursive allows for recursive calls of ClusterComputeResourceList
func (f *Finder) ComputeResourceListRecursive(ctx context.Context, path string, recursive bool) ([]*object.ComputeResource, error) {
	es, err := f.find(ctx, f.hostFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var crs []*object.ComputeResource
	for _, e := range es {
		var cr *object.ComputeResource

		switch o := e.Object.(type) {
		case mo.ComputeResource, mo.ClusterComputeResource:
			cr = object.NewComputeResource(f.client, o.Reference())
		default:
			continue
		}

		cr.InventoryPath = e.Path
		crs = append(crs, cr)
	}

	if len(crs) == 0 {
		return nil, &NotFoundError{"compute resource", path}
	}

	return crs, nil
}

func (f *Finder) ComputeResource(ctx context.Context, path string) (*object.ComputeResource, error) {
	crs, err := f.ComputeResourceList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(crs) > 1 {
		return nil, &MultipleFoundError{"compute resource", path}
	}

	return crs[0], nil
}

func (f *Finder) DefaultComputeResource(ctx context.Context) (*object.ComputeResource, error) {
	cr, err := f.ComputeResource(ctx, "*")
	if err != nil {
		return nil, toDefaultError(err)
	}

	return cr, nil
}

func (f *Finder) ClusterComputeResourceList(ctx context.Context, path string) ([]*object.ClusterComputeResource, error) {
	return f.ClusterComputeResourceListRecursive(ctx, path, false)
}

// ClusterComputeResourceList allows for recursive calls of ClusterComputeResource
func (f *Finder) ClusterComputeResourceListRecursive(ctx context.Context, path string, recursive bool) ([]*object.ClusterComputeResource, error) {
	es, err := f.find(ctx, f.hostFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var ccrs []*object.ClusterComputeResource
	for _, e := range es {
		var ccr *object.ClusterComputeResource

		switch o := e.Object.(type) {
		case mo.ClusterComputeResource:
			ccr = object.NewClusterComputeResource(f.client, o.Reference())
		default:
			continue
		}

		ccr.InventoryPath = e.Path
		ccrs = append(ccrs, ccr)
	}

	if len(ccrs) == 0 {
		return nil, &NotFoundError{"cluster", path}
	}

	return ccrs, nil
}

func (f *Finder) ClusterComputeResource(ctx context.Context, path string) (*object.ClusterComputeResource, error) {
	ccrs, err := f.ClusterComputeResourceList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(ccrs) > 1 {
		return nil, &MultipleFoundError{"cluster", path}
	}

	return ccrs[0], nil
}

func (f *Finder) HostSystemList(ctx context.Context, path string) ([]*object.HostSystem, error) {
	return f.HostSystemListRecursive(ctx, path, false)
}

// HostSystemListRecursive allows for recursive calls of HostSystemList
func (f *Finder) HostSystemListRecursive(ctx context.Context, path string, recursive bool) ([]*object.HostSystem, error) {
	es, err := f.find(ctx, f.hostFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var hss []*object.HostSystem
	for _, e := range es {
		var hs *object.HostSystem

		switch o := e.Object.(type) {
		case mo.HostSystem:
			hs = object.NewHostSystem(f.client, o.Reference())
		case mo.ComputeResource:
			cr := object.NewComputeResource(f.client, o.Reference())
			hosts, err := cr.Hosts(ctx)
			if err != nil {
				return nil, err
			}
			hs = object.NewHostSystem(f.client, hosts[0])
		default:
			continue
		}

		hs.InventoryPath = e.Path
		hss = append(hss, hs)
	}

	if len(hss) == 0 {
		return nil, &NotFoundError{"host", path}
	}

	return hss, nil
}

func (f *Finder) HostSystem(ctx context.Context, path string) (*object.HostSystem, error) {
	hss, err := f.HostSystemList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(hss) > 1 {
		return nil, &MultipleFoundError{"host", path}
	}

	return hss[0], nil
}

func (f *Finder) DefaultHostSystem(ctx context.Context) (*object.HostSystem, error) {
	hs, err := f.HostSystem(ctx, "*/*")
	if err != nil {
		return nil, toDefaultError(err)
	}

	return hs, nil
}

func (f *Finder) NetworksList(ctx context.Context, path string, recursive bool) ([]object.Network, error) {
	es, err := f.find(ctx, f.networkFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var ns []object.Network
	for _, e := range es {
		ref := e.Object.Reference()
		switch ref.Type {
		case "Network":
			r := object.NewNetwork(f.client, ref)
			r.InventoryPath = e.Path
			ns = append(ns, *r)
		}
	}

	return ns, nil
}

func (f *Finder) DVPGList(ctx context.Context, path string, recursive bool) ([]object.DistributedVirtualPortgroup, error) {
	es, err := f.find(ctx, f.networkFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var ns []object.DistributedVirtualPortgroup
	for _, e := range es {
		ref := e.Object.Reference()
		switch ref.Type {
		case "DistributedVirtualPortgroup":
			r := object.NewDistributedVirtualPortgroup(f.client, ref)
			r.InventoryPath = e.Path
			ns = append(ns, *r)
		}
	}
	return ns, nil
}

func (f *Finder) NetworkList(ctx context.Context, path string) ([]object.NetworkReference, error) {
	return f.NetworkListRecursive(ctx, path, false)
}

// NetworkListRecursive allows for recursive calls of NetworkList
func (f *Finder) NetworkListRecursive(ctx context.Context, path string, recursive bool) ([]object.NetworkReference, error) {
	es, err := f.find(ctx, f.networkFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var ns []object.NetworkReference
	for _, e := range es {
		ref := e.Object.Reference()
		switch ref.Type {
		case "Network":
			r := object.NewNetwork(f.client, ref)
			r.InventoryPath = e.Path
			ns = append(ns, r)
		case "DistributedVirtualPortgroup":
			r := object.NewDistributedVirtualPortgroup(f.client, ref)
			r.InventoryPath = e.Path
			ns = append(ns, r)
		}
	}

	if len(ns) == 0 {
		return nil, &NotFoundError{"network", path}
	}

	return ns, nil
}

func (f *Finder) Network(ctx context.Context, path string) (object.NetworkReference, error) {
	networks, err := f.NetworkList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(networks) > 1 {
		return nil, &MultipleFoundError{"network", path}
	}

	return networks[0], nil
}

func (f *Finder) DefaultNetwork(ctx context.Context) (object.NetworkReference, error) {
	network, err := f.Network(ctx, "*")
	if err != nil {
		return nil, toDefaultError(err)
	}

	return network, nil
}

func (f *Finder) ResourcePoolList(ctx context.Context, path string) ([]*object.ResourcePool, error) {
	return f.ResourcePoolListRecursive(ctx, path, true)
}

// ResourcePoolListRecursive allows for recursive calls to ResourcePoolList
func (f *Finder) ResourcePoolListRecursive(ctx context.Context, path string, recursive bool) ([]*object.ResourcePool, error) {
	es, err := f.find(ctx, f.hostFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var rps []*object.ResourcePool
	for _, e := range es {
		var rp *object.ResourcePool

		switch o := e.Object.(type) {
		case mo.ResourcePool:
			rp = object.NewResourcePool(f.client, o.Reference())
			rp.InventoryPath = e.Path
			rps = append(rps, rp)
		}
	}

	if len(rps) == 0 {
		return nil, &NotFoundError{"resource pool", path}
	}

	return rps, nil
}

func (f *Finder) ResourcePool(ctx context.Context, path string) (*object.ResourcePool, error) {
	rps, err := f.ResourcePoolList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(rps) > 1 {
		return nil, &MultipleFoundError{"resource pool", path}
	}

	return rps[0], nil
}

func (f *Finder) DefaultResourcePool(ctx context.Context) (*object.ResourcePool, error) {
	rp, err := f.ResourcePool(ctx, "*/Resources")
	if err != nil {
		return nil, toDefaultError(err)
	}

	return rp, nil
}

func (f *Finder) VirtualMachineList(ctx context.Context, path string) ([]*object.VirtualMachine, error) {
	return f.VirtualMachineListRecursive(ctx, path, false)
}

// VirtualMachineListRecursive allows for recursively calls to VirtualMachineList
func (f *Finder) VirtualMachineListRecursive(ctx context.Context, path string, recursive bool) ([]*object.VirtualMachine, error) {
	es, err := f.find(ctx, f.vmFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var vms []*object.VirtualMachine
	for _, e := range es {
		switch o := e.Object.(type) {
		case mo.VirtualMachine:
			vm := object.NewVirtualMachine(f.client, o.Reference())
			vm.InventoryPath = e.Path
			vms = append(vms, vm)
		}
	}

	if len(vms) == 0 {
		return nil, &NotFoundError{"vm", path}
	}

	return vms, nil
}

func (f *Finder) VirtualMachine(ctx context.Context, path string) (*object.VirtualMachine, error) {
	vms, err := f.VirtualMachineList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(vms) > 1 {
		return nil, &MultipleFoundError{"vm", path}
	}

	return vms[0], nil
}

func (f *Finder) VirtualAppList(ctx context.Context, path string) ([]*object.VirtualApp, error) {
	return f.VirtualAppListRecursive(ctx, path, false)
}

// VirtualAppList allows for recursive calls to VirtualAppList
func (f *Finder) VirtualAppListRecursive(ctx context.Context, path string, recursive bool) ([]*object.VirtualApp, error) {
	es, err := f.find(ctx, f.vmFolder, recursive, path)
	if err != nil {
		return nil, err
	}

	var apps []*object.VirtualApp
	for _, e := range es {
		switch o := e.Object.(type) {
		case mo.VirtualApp:
			app := object.NewVirtualApp(f.client, o.Reference())
			app.InventoryPath = e.Path
			apps = append(apps, app)
		}
	}

	if len(apps) == 0 {
		return nil, &NotFoundError{"app", path}
	}

	return apps, nil
}

func (f *Finder) VirtualApp(ctx context.Context, path string) (*object.VirtualApp, error) {
	apps, err := f.VirtualAppList(ctx, path)
	if err != nil {
		return nil, err
	}

	if len(apps) > 1 {
		return nil, &MultipleFoundError{"app", path}
	}

	return apps[0], nil
}
