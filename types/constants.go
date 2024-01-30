/*
 *     Copyright 2022 The Urchin Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import "time"

const (
	AuthRespHeader  = "PARA_TOKEN"
	AuthHeader      = "Authorization"
	TokenExpireTime = 60 * 60 * 24 * 27

	DefaultFileMode = 0644

	DefaultTokenExpireTime = time.Second * 60 * 60 * 24 * 11

	ParaTokenUrl = "https://user.paratera.com/"
	ParaCloudUrl = "https://eci.paracloud.com/"
)

const (
	StoragePrefix                = "urchin"
	StoragePrefixParaCloudVolume = "urchin:storage:paraCloud:webdav"
	StoragePrefixParaCloudToken  = "urchin:storage:paraCloud:token"
	StoragePrefixParaCloudConfig = "urchin:storage:paraCloud:config"
)

const (
	HttpMethodGet    = "get"
	HttpMethodPost   = "post"
	HttpMethodDelete = "delete"
)

const (
	BYTE = 1 << (10 * iota)
	KILOBYTE
	MEGABYTE
	GIGABYTE
	TERABYTE
	PETABYTE
	EXABYTE
)

const (
	GB_100 = 1024 * 1024 * 1024 * 100
	GB_10  = 1024 * 1024 * 1024 * 10
	GB_1   = 1024 * 1024 * 1024
	MB_500 = 1024 * 1024 * 500
	MB_100 = 1024 * 1024 * 100
)

const (
	// AffinitySeparator is separator of affinity.
	AffinitySeparator = "|"
)
